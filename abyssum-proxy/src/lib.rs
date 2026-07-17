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
pub mod ca;
pub mod error;
pub mod server;
pub mod store;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpListener;

pub use analysis::{Analysis, Flag, analyze};
pub use ca::CertAuthority;
pub use error::{Error, Result};
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
        }
    }
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

    let listener = TcpListener::bind(config.listen).await?;
    let local = listener.local_addr()?;
    tracing::info!(listen = %local, store = %config.store_path.display(), "observing proxy listening");
    tracing::info!(
        ca_cert = %config.ca_dir.join("ca_cert.pem").display(),
        "trust this CA on your test client to observe HTTPS traffic"
    );
    server.serve(listener).await
}
