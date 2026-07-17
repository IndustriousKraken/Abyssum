//! `abyssum-proxy` — the observing-proxy surface.
//!
//! A thin shell over [`abyssum_proxy`]: parse flags into a [`ProxyConfig`], set up
//! logging, and run the relay. All relay, capture, and storage logic lives in the
//! library so it stays testable and surface-independent.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use abyssum_proxy::{ProxyConfig, run};
use clap::Parser;

/// Abyssum observing proxy: relay HTTP/HTTPS traffic non-blockingly and capture
/// every exchange into a dedicated, queryable traffic store. For **authorized**
/// security testing only.
#[derive(Debug, Parser)]
#[command(name = "abyssum-proxy", version, about, long_about = None)]
struct Args {
    /// Address to listen on.
    #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Path to the SQLite traffic store.
    #[arg(long, value_name = "PATH", default_value = "data/proxy-traffic.db")]
    store: PathBuf,

    /// Directory holding the CA key + certificate (trust the cert on your client).
    #[arg(long, value_name = "DIR", default_value = "data/proxy-ca")]
    ca_dir: PathBuf,

    /// Max bytes of each body retained by capture (0 = keep everything).
    #[arg(long, value_name = "BYTES", default_value_t = 64 * 1024)]
    body_limit: usize,

    /// Bounded capacity of the capture channel.
    #[arg(long, value_name = "N", default_value_t = 1024)]
    capture_capacity: usize,

    /// Log verbosity (e.g. `info`, `debug`).
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    log_level: String,

    /// Do not verify TLS certificates of destinations (for targets with broken
    /// certs). Off by default.
    #[arg(long)]
    insecure_upstream: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level)),
        )
        .init();

    let config = ProxyConfig {
        listen: args.listen,
        store_path: args.store,
        ca_dir: args.ca_dir,
        body_limit: args.body_limit,
        capture_capacity: args.capture_capacity,
        insecure_upstream: args.insecure_upstream,
    };

    match run(config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("abyssum-proxy: {err}");
            ExitCode::FAILURE
        }
    }
}
