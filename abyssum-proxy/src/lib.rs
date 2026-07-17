//! Abyssum observing proxy — core (pass-through + capture).
//!
//! A lightweight proxy that **observes and filters** API traffic — deliberately
//! *not* an intercepting proxy. It relays HTTP/HTTPS between a client and its
//! destination without ever pausing the operator on a breakpoint or altering
//! traffic in flight, and captures every exchange into a dedicated, queryable
//! SQLite traffic store — asynchronously, so a slow store never stalls the client.
//!
//! - [`server::ProxyServer`] — the non-blocking relay (TLS-terminating via a local
//!   CA so HTTPS content is observable).
//! - [`store::TrafficStore`] — the dedicated, persistent, queryable traffic store,
//!   fed off the hot path through a [`store::CaptureSink`].
//! - [`ca::CertAuthority`] — the locally-generated CA and per-host leaf certs.
//!
//! [`run`] wires these together from a [`ProxyConfig`] for the binary.

pub mod analysis;
pub mod api;
pub mod ca;
pub mod error;
pub mod export;
pub mod replay;
pub mod server;
pub mod store;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use abyssum_core::{
    CancellationToken, Config, RateLimiter, RotatingUserAgent, ScanContext, UserAgentRotation,
};
use tokio::net::TcpListener;

pub use analysis::{Analysis, Flag, analyze};
pub use api::ApiState;
pub use ca::CertAuthority;
pub use error::{Error, Result};
pub use export::{ExportFormat, to_har, to_openapi, to_postman, to_raw};
pub use replay::{ReplayModifications, Replayer};
pub use server::ProxyServer;
pub use store::{CaptureSink, CapturedExchange, StoredExchange, TrafficQuery, TrafficStore};

/// How the observing proxy is configured. Every field has a sensible default via
/// [`ProxyConfig::default`]; the binary overlays CLI flags onto it.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address the proxy listens on.
    pub listen: SocketAddr,
    /// Path to the dedicated SQLite traffic store.
    pub store_path: PathBuf,
    /// Directory holding the CA key + certificate (created if absent).
    pub ca_dir: PathBuf,
    /// Maximum bytes of each request/response body retained by capture (`0` = all).
    pub body_limit: usize,
    /// Bounded capacity of the capture channel; captures beyond it are dropped so
    /// the relay is never stalled by a slow store.
    pub capture_capacity: usize,
    /// Disable TLS verification on the outbound leg (targets with broken certs).
    pub insecure_upstream: bool,
    /// If set, also serve the read-only traffic API (query/export/replay) on this
    /// address, so external tools and agents can consume the capture. Off by default.
    pub api_listen: Option<SocketAddr>,
    /// Shared-secret bearer token gating the traffic API. When set, every API
    /// request must carry `Authorization: Bearer <token>`. REQUIRED to bind
    /// [`api_listen`](Self::api_listen) to a non-loopback address, because the API
    /// can read and replay captured credentials (`Authorization`/`Cookie` headers).
    pub api_token: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            store_path: PathBuf::from("data/proxy-traffic.db"),
            ca_dir: PathBuf::from("data/proxy-ca"),
            body_limit: 64 * 1024,
            capture_capacity: 1024,
            insecure_upstream: false,
            api_listen: None,
            api_token: None,
        }
    }
}

/// Build the paced [`Replayer`] over the traffic store: a [`ScanContext`] carrying
/// the shared pacing floor (from the default scanning config) and a rotating,
/// realistic User-Agent pool, so a replayed request respects the same
/// infrastructure-respect posture as a scan. The UA pool falls back to the bundled
/// realistic identities when the store is unseeded (see `RotatingUserAgent::new`).
fn build_replayer(store: TrafficStore, body_limit: usize) -> Replayer {
    let config = Config::default();
    let rate_limiter = RateLimiter::from_config(&config.scanning);
    let ua = Arc::new(RotatingUserAgent::new(
        Vec::new(),
        UserAgentRotation::PerRequest,
    ));
    let ctx = ScanContext::new(Arc::new(config), rate_limiter, ua, CancellationToken::new());
    Replayer::new(ctx, store, body_limit)
}

/// Open the traffic store, spawn its writer, load/create the CA, bind the listener,
/// and relay forever. Returns only on a fatal bind/accept error.
pub async fn run(config: ProxyConfig) -> Result<()> {
    let store = TrafficStore::open(&config.store_path).await?;
    let sink = store.spawn_writer(config.capture_capacity);
    let ca = Arc::new(CertAuthority::load_or_create(&config.ca_dir).await?);
    let server = Arc::new(ProxyServer::new(
        ca,
        sink,
        config.body_limit,
        config.insecure_upstream,
    )?);

    // Optionally serve the read-only traffic API (query/export/replay) so external
    // tools and agents can consume the capture. Replay goes out through the paced
    // send path, so it respects the same pacing floor and UA rotation as a scan.
    if let Some(api_addr) = config.api_listen {
        // The API can read and replay captured credentials (`Authorization`/`Cookie`
        // live in the store), so refuse to expose it on a non-loopback address unless
        // it is gated by a shared-secret token — otherwise anyone who can reach it
        // could exfiltrate those credentials. Loopback with no token stays allowed.
        if !api_addr.ip().is_loopback() && config.api_token.is_none() {
            return Err(Error::Config(format!(
                "refusing to bind the traffic API to non-loopback {api_addr} without \
                 --api-token: it exposes captured credentials to anyone who can reach it"
            )));
        }
        let replayer = build_replayer(store.clone(), config.body_limit);
        let state = Arc::new(ApiState {
            store,
            replayer,
            token: config.api_token.clone(),
        });
        let api_listener = TcpListener::bind(api_addr).await?;
        let local_api = api_listener.local_addr()?;
        tracing::info!(listen = %local_api, "observing-proxy read/replay API listening");
        tokio::spawn(async move {
            if let Err(e) = api::serve(api_listener, state).await {
                tracing::error!(error = %e, "traffic API stopped");
            }
        });
    }

    let listener = TcpListener::bind(config.listen).await?;
    let local = listener.local_addr()?;
    tracing::info!(listen = %local, store = %config.store_path.display(), "observing proxy listening");
    tracing::info!(
        ca_cert = %config.ca_dir.join("ca_cert.pem").display(),
        "trust this CA on your test client to observe HTTPS traffic"
    );
    server.serve(listener).await
}
