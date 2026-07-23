//! CLI credential-flag integration test — local only, no real targets.
//!
//! Proves the `--cookie` / `--bearer` flags reach scanner requests: a scan with
//! either flag sends the credential to the target, and a scan with neither sends
//! none. Driven in-process through [`abyssum_cli::execute`] against a recording
//! mock server that logs each request's headers.

use std::net::SocketAddr;

use abyssum_cli::{Cli, OutputFormat, execute};

mod common;
use common::{spawn_recording_cors_mock, write_config};

/// A `cors` scan of `addr`, storing to a temp DB, with the given credential flags.
fn scan_cli(
    addr: SocketAddr,
    config: String,
    cookie: Option<String>,
    bearer: Option<String>,
) -> Cli {
    Cli {
        command: None,
        targets: vec![format!("http://{addr}")],
        scanners: vec!["cors".to_string()],
        identities: vec![],
        cookie,
        bearer,
        bruteforce: false,
        min_delay: None,
        max_delay: None,
        log_level: None,
        output: OutputFormat::Table,
        config,
    }
}

#[tokio::test]
async fn cookie_and_bearer_flags_send_the_credential() {
    let (addr, log) = spawn_recording_cors_mock().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &dir.path().join("abyssum.db"));

    let cli = scan_cli(
        addr,
        cfg.to_string_lossy().into_owned(),
        Some("session=abc123".to_string()),
        Some("tok-secret".to_string()),
    );
    execute(cli).await.expect("the scan should complete");

    // Every credentialed request carried both the bearer token and the cookie.
    let heads = log.lock().unwrap().join("\n");
    assert!(
        heads.contains("tok-secret"),
        "the bearer token must reach the target; got:\n{heads}"
    );
    assert!(
        heads.contains("session=abc123"),
        "the cookie must reach the target; got:\n{heads}"
    );
}

#[tokio::test]
async fn no_flags_sends_no_credential() {
    let (addr, log) = spawn_recording_cors_mock().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &dir.path().join("abyssum.db"));

    let cli = scan_cli(addr, cfg.to_string_lossy().into_owned(), None, None);
    execute(cli).await.expect("the scan should complete");

    // No credential was attached, so no Authorization / Cookie header went out.
    let heads = log.lock().unwrap().join("\n").to_lowercase();
    assert!(
        !heads.contains("authorization:"),
        "no Authorization header expected; got:\n{heads}"
    );
    assert!(
        !heads.contains("cookie:"),
        "no Cookie header expected; got:\n{heads}"
    );
}
