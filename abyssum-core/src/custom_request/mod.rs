//! The custom-requests tool: a manual escape hatch alongside the scanners.
//!
//! This is a manual **tool**, not a scanner. It fires exactly one operator-chosen
//! HTTP request per invocation — any method, headers, and body — captures the full
//! response, and surfaces advisory security signals for manual follow-up. It does
//! not implement the [`BaseScanner`](crate::BaseScanner) trait, produces no
//! persisted findings, and is exempt from the scan engine's progress/cancellation
//! machinery. Living in `core` lets both surfaces (CLI and web) drive one code path
//! and render the same result.
//!
//! Pipeline:
//!
//! ```text
//! CustomRequestSpec
//!   -> prepare()   normalize URL/method, fold in auth + content-type headers
//!   -> acquire pacing for the target host (shared RateLimiter)
//!   -> send via a per-invocation reqwest client (TLS-verify + redirect policy)
//!   -> capture status, headers, body, timing, final URL + redirect hop count
//!   -> analyze(response)  (pure: advisory signals)
//!   -> RequestOutcome { request echo, response|error, signals }
//! ```
//!
//! Auth is additive and optional: absent token → no `Authorization`; absent cookie
//! → no `Cookie`; absent both → a keyless request (first-class, per canon). A
//! transport failure or timeout is captured into the result rather than panicking.
//!
//! Outbound requests are paced through the shared [`RateLimiter`] exactly as scanner
//! requests are: the first request to a host is free, and subsequent requests to the
//! same host (within the same limiter's lifetime) honor the configured per-domain
//! delay and backoff. This keeps the tool consistent with the project's
//! infrastructure-respect posture and keeps it from becoming a scripted DoS
//! primitive.

mod analysis;
mod output;
mod response;
mod spec;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use url::Url;

use crate::rate_limiter::{Pace, RateLimiter};

pub use analysis::{analyze, Signal, SignalKind};
pub use output::OutputFormat;
pub use response::{CaptureResult, CapturedResponse, RequestOutcome};
pub use spec::{CustomRequestSpec, PreparedRequest, DEFAULT_BODY_PREVIEW_CAP, DEFAULT_TIMEOUT};

use spec::MAX_REDIRECTS;

/// Send one custom request and return the captured outcome.
///
/// The request is paced through `limiter` (first request to a host is free;
/// subsequent ones honor the per-domain delay/backoff), then sent through a
/// short-lived client built for this invocation's TLS-verify and redirect settings.
/// A transport error, timeout, or pacing halt is captured into the returned
/// [`RequestOutcome`] — this function does not panic on a failed request.
pub async fn execute(spec: &CustomRequestSpec, limiter: &RateLimiter) -> RequestOutcome {
    let cap = spec.body_preview_cap;

    // Resolve the request. Only an unparseable URL fails here; keep a best-effort
    // echo so the error output still shows what was attempted.
    let prepared = match spec.prepare() {
        Ok(prepared) => prepared,
        Err(err) => return RequestOutcome::failed(spec.raw_echo(), err, cap),
    };

    // The normalized URL parsed cleanly in `prepare`; re-parse for host + sending.
    let url = match Url::parse(&prepared.url) {
        Ok(url) => url,
        Err(err) => return RequestOutcome::failed(prepared, format!("invalid URL: {err}"), cap),
    };

    // Pace through the shared limiter before any bytes leave (first request free).
    if let Some(host) = url.host_str() {
        if matches!(limiter.acquire(host).await, Pace::Halt) {
            let msg = format!("pacing halted the request to {host}: sustained target distress");
            return RequestOutcome::failed(prepared, msg, cap);
        }
    }

    let redirects = Arc::new(AtomicUsize::new(0));
    let client = match build_client(spec, redirects.clone()) {
        Ok(client) => client,
        Err(err) => return RequestOutcome::failed(prepared, err, cap),
    };

    match send_and_capture(&client, &prepared, &url, &redirects).await {
        Ok(response) => {
            // Feed the outcome back into the limiter so distress grows backoff and
            // clean completions decay it — exactly as the scanner path does.
            if let Some(host) = url.host_str() {
                limiter.record_signal(host, response.status).await;
            }
            let signals = analyze(&response);
            RequestOutcome {
                request: prepared,
                result: CaptureResult::Response(response),
                signals,
                body_preview_cap: cap,
            }
        }
        Err(err) => RequestOutcome::failed(prepared, err, cap),
    }
}

impl RequestOutcome {
    /// An outcome that carries a transport/pacing error and no response or signals.
    fn failed(request: PreparedRequest, error: String, cap: usize) -> Self {
        Self {
            request,
            result: CaptureResult::Error(error),
            signals: Vec::new(),
            body_preview_cap: cap,
        }
    }
}

/// Build the per-invocation HTTP client. TLS verification is on unless the spec
/// opts out (`--insecure`), redirects are followed only when requested (counting
/// hops up to [`MAX_REDIRECTS`]), and the timeout bounds the whole round trip.
fn build_client(
    spec: &CustomRequestSpec,
    redirects: Arc<AtomicUsize>,
) -> Result<reqwest::Client, String> {
    let policy = if spec.follow_redirects {
        reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                attempt.error("too many redirects")
            } else {
                redirects.fetch_add(1, Ordering::Relaxed);
                attempt.follow()
            }
        })
    } else {
        reqwest::redirect::Policy::none()
    };

    reqwest::Client::builder()
        .redirect(policy)
        // TLS verification ON by default; relaxed only for this single request when
        // the operator explicitly opted out.
        .danger_accept_invalid_certs(!spec.verify_tls)
        .timeout(spec.timeout)
        .build()
        .map_err(|e| format!("failed to build HTTP client: {e}"))
}

/// Issue the prepared request and capture the full response (or the transport
/// error). Timing spans from just before send to the body being fully read.
async fn send_and_capture(
    client: &reqwest::Client,
    prepared: &PreparedRequest,
    url: &Url,
    redirects: &Arc<AtomicUsize>,
) -> Result<CapturedResponse, String> {
    let method = reqwest::Method::from_bytes(prepared.method.as_bytes())
        .map_err(|e| format!("invalid method {:?}: {e}", prepared.method))?;

    let mut builder = client.request(method, url.clone());
    for (name, value) in &prepared.headers {
        builder = builder.header(name, value);
    }
    if let Some(body) = &prepared.body {
        builder = builder.body(body.clone());
    }

    let started = Instant::now();
    let response = builder.send().await.map_err(|e| e.to_string())?;

    let status = response.status().as_u16();
    let final_url = response.url().to_string();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let bytes = response.bytes().await.map_err(|e| e.to_string())?;
    let elapsed = started.elapsed();
    let body = String::from_utf8_lossy(&bytes).into_owned();

    Ok(CapturedResponse {
        status,
        headers,
        body,
        elapsed,
        final_url,
        redirect_count: redirects.load(Ordering::Relaxed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn no_pacing() -> RateLimiter {
        RateLimiter::new(Duration::ZERO, Duration::ZERO)
    }

    #[tokio::test]
    async fn unparseable_url_yields_error_outcome_not_panic() {
        let spec = CustomRequestSpec::new("   ");
        let outcome = execute(&spec, &no_pacing()).await;
        assert!(outcome.response().is_none());
        assert!(outcome.error().is_some());
        // The echo still reflects the attempt.
        assert_eq!(outcome.request.method, "GET");
    }
}
