//! Shared helpers for the `abyssum` CLI integration tests.
//!
//! Both the in-process end-to-end test (`e2e.rs`) and the subprocess exit-code
//! tests (`exit_codes.rs`) drive a scan against the same local permissive-CORS
//! mock server with the store pointed at a temp config. The mock protocol and the
//! config format live here, in one place, so the two test files cannot drift.
//!
//! Each integration-test binary compiles this module independently and uses only
//! the helpers it needs (the report tests, for instance, need only `write_config`),
//! so an unused helper in one binary is expected — hence the module-wide allow.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Spawn a local HTTP server that answers every request with a permissive CORS
/// policy (`Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials:
/// true`), which the `cors` scanner reports as a finding. Returns the bound
/// address; the accept loop runs detached for the test's duration.
pub async fn spawn_cors_mock() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            tokio::spawn(async move {
                // Read the request headers (best effort — a GET carries no body).
                let mut buf = vec![0u8; 2048];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 200 OK\r\n\
                     Access-Control-Allow-Origin: *\r\n\
                     Access-Control-Allow-Credentials: true\r\n\
                     Content-Length: 0\r\n\
                     Connection: close\r\n\
                     \r\n";
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    addr
}

/// Write a config that points the store at `db_path` and drops the pacing floor to
/// zero (an authorized local test against a mock — no need to wait), returning the
/// config file's path.
pub fn write_config(dir: &Path, db_path: &Path) -> PathBuf {
    let cfg_path = dir.join("abyssum.yaml");
    let contents = format!(
        "database:\n  path: {db}\nscanning:\n  min_delay: 0.0\n  max_delay: 0.0\nlog:\n  level: warn\n",
        db = db_path.display()
    );
    std::fs::write(&cfg_path, contents).unwrap();
    cfg_path
}
