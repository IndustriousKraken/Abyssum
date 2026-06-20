//! The scan context handed to every scanner at run time.
//!
//! A scanner owns none of the cross-cutting concerns. They arrive in a
//! [`ScanContext`]: the shared [`RateLimiter`], a [`UserAgentSource`], an
//! optional progress callback, a cancellation signal, and an optional
//! [`Credential`]. Crucially the scanner is given **no raw HTTP client** — the
//! only path to the network is [`ScanContext::send`], which paces through the
//! limiter and stamps a User-Agent before sending. That makes the pacing floor
//! *structurally* unbypassable: there is simply no other way out.

use std::sync::Arc;

use reqwest::header::{COOKIE, USER_AGENT};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::rate_limit::{Pace, RateLimiter};

use super::progress::{ProgressCallback, ProgressUpdate};

/// The default User-Agent for the single-identity source. `add-seed-data` (a04)
/// swaps in a rotating pool of realistic agents without this type changing.
pub const DEFAULT_USER_AGENT: &str = concat!("Abyssum/", env!("CARGO_PKG_VERSION"));

/// Source of the User-Agent string stamped on each outbound request.
///
/// This change ships a trivial single-identity default ([`SingleUserAgent`]);
/// `add-seed-data` replaces it with the rotating realistic pool, and because the
/// context depends only on this trait, [`ScanContext`] never changes shape.
pub trait UserAgentSource: Send + Sync {
    /// Yield the User-Agent to stamp on the next request.
    fn next_user_agent(&self) -> String;
}

/// The default source: always returns one fixed identity.
#[derive(Debug, Clone)]
pub struct SingleUserAgent {
    user_agent: String,
}

impl SingleUserAgent {
    /// Build a single-identity source from a specific User-Agent string.
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self {
            user_agent: user_agent.into(),
        }
    }
}

impl Default for SingleUserAgent {
    fn default() -> Self {
        Self::new(DEFAULT_USER_AGENT)
    }
}

impl UserAgentSource for SingleUserAgent {
    fn next_user_agent(&self) -> String {
        self.user_agent.clone()
    }
}

/// An optional credential attached to outbound requests: a bearer token and/or a
/// cookie. CORS attaches one; BAC/IDOR can run with it stripped to compare.
///
/// `Debug` is implemented by hand to **redact** the secret values: it reports
/// only whether a bearer/cookie is present, never the value itself. This keeps a
/// stray `tracing::debug!(credential = ?cred)` or a `#[derive(Debug)]` on a
/// future containing type from leaking secrets into logs.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    /// Bearer token sent as `Authorization: Bearer <token>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bearer: Option<String>,
    /// Raw `Cookie:` header value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<String>,
}

impl std::fmt::Debug for Credential {
    /// Redact the secret values, preserving only their presence/absence so a
    /// debug print stays diagnostically useful without exposing the token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |value: &Option<String>| value.as_ref().map(|_| "***");
        f.debug_struct("Credential")
            .field("bearer", &redact(&self.bearer))
            .field("cookie", &redact(&self.cookie))
            .finish()
    }
}

impl Credential {
    /// A credential carrying only a bearer token.
    pub fn bearer(token: impl Into<String>) -> Self {
        Self {
            bearer: Some(token.into()),
            cookie: None,
        }
    }

    /// A credential carrying only a cookie.
    pub fn cookie(cookie: impl Into<String>) -> Self {
        Self {
            bearer: None,
            cookie: Some(cookie.into()),
        }
    }
}

/// An HTTP method for a [`RequestSpec`]. Re-exported from `reqwest` so the
/// context and the client agree on the type without scanners depending on
/// `reqwest` directly for the common cases.
pub use reqwest::Method;

/// A request a scanner asks the context to send. The scanner describes *what* to
/// send; the context decides *how* (pacing, User-Agent, credential) — the scanner
/// never holds a client.
#[derive(Debug, Clone)]
pub struct RequestSpec {
    /// HTTP method.
    pub method: Method,
    /// Absolute request URL (its host keys the pacing).
    pub url: Url,
    /// Extra request headers (the engine still owns User-Agent and credentials).
    pub headers: Vec<(String, String)>,
    /// Optional request body.
    pub body: Option<Vec<u8>>,
}

impl RequestSpec {
    /// A GET request for `url`.
    pub fn get(url: Url) -> Self {
        Self::new(Method::GET, url)
    }

    /// A request with an explicit method.
    pub fn new(method: Method, url: Url) -> Self {
        Self {
            method,
            url,
            headers: Vec::new(),
            body: None,
        }
    }

    /// Add a header (builder-style).
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the body (builder-style).
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }
}

/// Everything a scanner is handed when it runs. Cheaply cloneable (every field is
/// `Arc`-backed or itself cheap), so the orchestrator builds one per
/// scanner-target unit at negligible cost.
#[derive(Clone)]
pub struct ScanContext {
    config: Arc<Config>,
    rate_limiter: RateLimiter,
    ua_source: Arc<dyn UserAgentSource>,
    http: reqwest::Client,
    progress: Option<ProgressCallback>,
    cancel: CancellationToken,
    auth: Option<Credential>,
}

impl ScanContext {
    /// Build a context from its required parts. Optional concerns (progress,
    /// credential, a shared HTTP client) are layered on with the `with_*`
    /// builders. The orchestrator is the usual constructor; this is also handy
    /// for scanner unit tests.
    pub fn new(
        config: Arc<Config>,
        rate_limiter: RateLimiter,
        ua_source: Arc<dyn UserAgentSource>,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            config,
            rate_limiter,
            ua_source,
            http: reqwest::Client::new(),
            progress: None,
            cancel,
            auth: None,
        }
    }

    /// Reuse a shared `reqwest::Client` (connection pooling) instead of the
    /// per-context default.
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http = client;
        self
    }

    /// Attach the progress callback (builder-style).
    pub fn with_progress(mut self, callback: ProgressCallback) -> Self {
        self.progress = Some(callback);
        self
    }

    /// Attach a credential (builder-style).
    pub fn with_credential(mut self, credential: Credential) -> Self {
        self.auth = Some(credential);
        self
    }

    /// The loaded runtime configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The credential attached to this context, if any.
    pub fn credential(&self) -> Option<&Credential> {
        self.auth.as_ref()
    }

    /// Report progress to the context's callback. A no-op when no callback is
    /// attached, so scanners can always call it unconditionally.
    pub fn report_progress(&self, update: ProgressUpdate) {
        if let Some(callback) = &self.progress {
            callback(update);
        }
    }

    /// Whether cancellation has been signalled.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// Returns [`Error::Cancelled`] if cancellation has been signalled, else
    /// `Ok(())`. A cooperating scanner calls this at loop points to unwind
    /// promptly and return the findings gathered so far.
    pub async fn check_cancellation(&self) -> Result<()> {
        if self.cancel.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }

    /// A clone of the cancellation token, for a scanner that wants to *await*
    /// cancellation (e.g. to race it against its own work).
    pub fn cancellation_token(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// The **only** outbound path. Acquires the rate limiter for the request's
    /// host, stamps a User-Agent from the [`UserAgentSource`], attaches any
    /// credential, sends, and feeds the response status back to the limiter's
    /// adaptive backoff. No client is exposed to the scanner, so this floor
    /// cannot be skipped.
    pub async fn send(&self, request: RequestSpec) -> Result<reqwest::Response> {
        let host = request
            .url
            .host_str()
            .ok_or_else(|| Error::Target(format!("request URL has no host: {}", request.url)))?
            .to_string();

        // Pace first — the floor is enforced here, before any bytes leave.
        match self.rate_limiter.acquire(&host).await {
            Pace::Halt => {
                return Err(Error::Http(format!(
                    "pacing halted further requests to {host}: sustained target distress"
                )))
            }
            Pace::Proceed => {}
        }

        let mut builder = self
            .http
            .request(request.method, request.url.clone())
            .header(USER_AGENT, self.ua_source.next_user_agent());

        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        if let Some(credential) = &self.auth {
            if let Some(bearer) = &credential.bearer {
                builder = builder.bearer_auth(bearer);
            }
            if let Some(cookie) = &credential.cookie {
                builder = builder.header(COOKIE, cookie);
            }
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| Error::Http(e.to_string()))?;

        // Feed the response back into the limiter so distress grows backoff and
        // clean completions decay it.
        self.rate_limiter
            .record_signal(&host, response.status().as_u16())
            .await;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    fn ctx(cancel: CancellationToken) -> ScanContext {
        ScanContext::new(
            Arc::new(Config::default()),
            RateLimiter::new(Duration::ZERO, Duration::ZERO),
            Arc::new(SingleUserAgent::default()),
            cancel,
        )
    }

    #[test]
    fn single_user_agent_returns_fixed_identity() {
        let src = SingleUserAgent::default();
        assert_eq!(src.next_user_agent(), DEFAULT_USER_AGENT);
        assert!(src.next_user_agent().starts_with("Abyssum/"));
    }

    #[test]
    fn credential_constructors() {
        assert_eq!(Credential::bearer("t").bearer.as_deref(), Some("t"));
        assert_eq!(Credential::cookie("c").cookie.as_deref(), Some("c"));
    }

    #[test]
    fn credential_debug_redacts_secret_values() {
        let cred = Credential {
            bearer: Some("super-secret-token".into()),
            cookie: Some("session=hunter2".into()),
        };
        let rendered = format!("{cred:?}");
        // The secret values must never appear in a debug print.
        assert!(!rendered.contains("super-secret-token"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        // Presence is still reported (redacted), absence stays None.
        assert!(rendered.contains("***"), "{rendered}");
        assert_eq!(
            format!("{:?}", Credential::default()),
            "Credential { bearer: None, cookie: None }"
        );
    }

    #[tokio::test]
    async fn report_progress_is_a_noop_without_callback() {
        let c = ctx(CancellationToken::new());
        // No panic, nothing observed.
        c.report_progress(ProgressUpdate::new("s", 1, 1));
    }

    #[tokio::test]
    async fn report_progress_forwards_to_callback() {
        let seen: Arc<Mutex<Vec<ProgressUpdate>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let c = ctx(CancellationToken::new())
            .with_progress(Arc::new(move |u| sink.lock().unwrap().push(u)));
        c.report_progress(ProgressUpdate::new("s", 2, 4).current_item("/x"));
        let got = seen.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].current_item.as_deref(), Some("/x"));
    }

    #[tokio::test]
    async fn cancellation_is_observable() {
        let token = CancellationToken::new();
        let c = ctx(token.clone());
        assert!(!c.is_cancelled());
        assert!(c.check_cancellation().await.is_ok());

        token.cancel();
        assert!(c.is_cancelled());
        assert!(matches!(
            c.check_cancellation().await,
            Err(Error::Cancelled)
        ));
    }

    #[tokio::test]
    async fn send_rejects_url_without_host() {
        let c = ctx(CancellationToken::new());
        let url = Url::parse("file:///etc/passwd").unwrap();
        let err = c.send(RequestSpec::get(url)).await.unwrap_err();
        assert!(matches!(err, Error::Target(_)), "got {err:?}");
    }
}
