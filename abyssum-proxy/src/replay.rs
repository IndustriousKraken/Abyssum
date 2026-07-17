//! Replay a captured request with operator-specified modifications.
//!
//! A replayed request is **active traffic**, so it must respect the same
//! infrastructure-respect posture as a scan (see `design.md` and
//! `openspec/project.md`): it goes out through
//! [`ScanContext::send`](abyssum_core::ScanContext::send) — the engine's single
//! outbound chokepoint — so the pacing floor and rotating User-Agent apply to it
//! exactly as they do to a scanner. There is deliberately no separate, unpaced
//! send path for replay. The response is then captured into the traffic store like
//! any other exchange.

use std::time::Instant;

use abyssum_core::{Method, RequestSpec, ScanContext};
use chrono::Utc;

use crate::error::{Error, Result};
use crate::server::{cap, param_names};
use crate::store::{CapturedExchange, StoredExchange, TrafficStore};

/// Operator-specified changes to apply to a captured request before re-issuing it.
/// Every field is optional; an absent field reuses the captured request's value.
#[derive(Debug, Clone, Default)]
pub struct ReplayModifications {
    /// Override the HTTP method.
    pub method: Option<String>,
    /// Override the full request URL.
    pub url: Option<String>,
    /// Replace the request headers wholesale (engine-owned headers — `Host`,
    /// `Content-Length`, `User-Agent`, and hop-by-hop — are dropped either way).
    pub headers: Option<Vec<(String, String)>>,
    /// Replace the request body.
    pub body: Option<Vec<u8>>,
}

/// Issues replays through the paced send path and captures their responses.
///
/// Cheaply cloneable (both fields are `Arc`-backed), so the read API can share one
/// across requests.
#[derive(Clone)]
pub struct Replayer {
    ctx: ScanContext,
    store: TrafficStore,
    body_limit: usize,
}

impl Replayer {
    /// Build a replayer over a [`ScanContext`] (which owns the pacing floor and
    /// User-Agent rotation) and the traffic store the response is captured into.
    /// `body_limit` caps the captured bodies exactly as the relay's capture does.
    pub fn new(ctx: ScanContext, store: TrafficStore, body_limit: usize) -> Self {
        Self {
            ctx,
            store,
            body_limit,
        }
    }

    /// Load the stored exchange `id`, apply `mods`, re-issue it through the paced
    /// send path, and capture the response. Returns the newly stored exchange.
    pub async fn replay_stored(
        &self,
        id: i64,
        mods: &ReplayModifications,
    ) -> Result<StoredExchange> {
        let base = self
            .store
            .get(id)
            .await?
            .ok_or_else(|| Error::Store(format!("no captured exchange with id {id}")))?;
        self.replay(&base.exchange, mods).await
    }

    /// Apply `mods` to `base`, re-issue through [`ScanContext::send`] (paced,
    /// User-Agent-rotated), and capture the response into the store.
    pub async fn replay(
        &self,
        base: &CapturedExchange,
        mods: &ReplayModifications,
    ) -> Result<StoredExchange> {
        // Resolve the request from the base exchange overlaid with the operator's
        // modifications.
        let method_str = mods.method.as_deref().unwrap_or(&base.method);
        let method = Method::from_bytes(method_str.as_bytes())
            .map_err(|e| Error::Upstream(format!("invalid replay method {method_str:?}: {e}")))?;

        let url_str = mods.url.as_deref().unwrap_or(&base.url);
        let url = url::Url::parse(url_str)
            .map_err(|e| Error::Upstream(format!("invalid replay URL {url_str:?}: {e}")))?;

        let source_headers = mods.headers.as_ref().unwrap_or(&base.req_headers);
        let headers: Vec<(String, String)> = source_headers
            .iter()
            .filter(|(name, _)| is_forwardable(name))
            .cloned()
            .collect();

        let body = mods.body.clone().unwrap_or_else(|| base.req_body.clone());

        let mut spec = RequestSpec::new(method.clone(), url.clone());
        spec.headers = headers.clone();
        if !body.is_empty() {
            spec = spec.body(body.clone());
        }

        // The single outbound path: paced + User-Agent-stamped. No unpaced escape.
        let started_at = Utc::now();
        let t0 = Instant::now();
        let response = self
            .ctx
            .send(spec)
            .await
            .map_err(|e| Error::Upstream(format!("replay request failed: {e}")))?;

        let status = response.status().as_u16();
        let resp_headers = header_pairs(response.headers());
        let resp_bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Upstream(format!("reading replay response: {e}")))?;
        let duration_ms = i64::try_from(t0.elapsed().as_millis()).unwrap_or(i64::MAX);

        // Capture the replayed exchange like any other — same cap + record path.
        let query = url.query().map(str::to_string);
        let (req_body, req_truncated) = cap(&bytes::Bytes::from(body), self.body_limit);
        let (resp_body, resp_truncated) = cap(&resp_bytes, self.body_limit);
        let exchange = CapturedExchange {
            method: method.to_string(),
            url: url.to_string(),
            host: url.host_str().unwrap_or_default().to_string(),
            endpoint: url.path().to_string(),
            params: param_names(query.as_deref()),
            query,
            req_headers: headers,
            req_body,
            req_body_truncated: req_truncated,
            status,
            resp_headers,
            resp_body,
            resp_body_truncated: resp_truncated,
            started_at,
            duration_ms,
        };

        // record analyses internally but does not hand the analysis back; re-run it
        // so the returned StoredExchange carries the flags/score that were persisted.
        let id = self.store.record(&exchange).await?;
        let analysis = crate::analysis::analyze(&exchange);
        Ok(StoredExchange {
            id,
            exchange,
            flags: analysis.flags,
            score: analysis.score,
        })
    }
}

/// Whether a captured request header should be forwarded on replay. The engine owns
/// `Host` and `Content-Length` (reqwest sets them from the URL and body), stamps its
/// own rotating `User-Agent`, and never forwards hop-by-hop headers — so those are
/// dropped from the replay request just as the relay drops them.
fn is_forwardable(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    !matches!(
        name.as_str(),
        "host"
            | "content-length"
            | "user-agent"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Convert a response header map to captured (name, value) pairs (values lossy).
fn header_pairs(headers: &http::HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}
