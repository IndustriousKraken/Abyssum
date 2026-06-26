//! Process exit-code tests for the `abyssum` binary (task 7.3) — local only.
//!
//! Each test runs the built binary as a subprocess and asserts its exit status:
//! `0` on a completed scan (against a local mock HTTP server), and a non-zero
//! status for invalid input (an unknown scanner id, an unparseable target) — which
//! is rejected before any request is issued.

mod common;
use common::{spawn_cors_mock, write_config};

/// Path to the built `abyssum` binary, provided by Cargo.
fn abyssum_bin() -> &'static str {
    env!("CARGO_BIN_EXE_abyssum")
}

#[tokio::test]
async fn exit_zero_on_a_completed_scan() {
    let addr = spawn_cors_mock().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &dir.path().join("abyssum.db"));

    let output = tokio::process::Command::new(abyssum_bin())
        .arg("--config")
        .arg(&cfg)
        .arg("--targets")
        .arg(format!("http://{addr}"))
        .arg("--scanners")
        .arg("cors")
        .arg("--output")
        .arg("json")
        .output()
        .await
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // The findings were rendered to stdout in the requested format.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("cors"), "stdout: {stdout}");
}

#[test]
fn exit_nonzero_on_unknown_scanner() {
    let dir = tempfile::tempdir().unwrap();
    // A temp store so the rejected run never writes to the repository's data dir.
    let cfg = write_config(dir.path(), &dir.path().join("abyssum.db"));

    let output = std::process::Command::new(abyssum_bin())
        .arg("--config")
        .arg(&cfg)
        .arg("--targets")
        .arg("http://127.0.0.1:9")
        .arg("--scanners")
        .arg("does_not_exist")
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn exit_nonzero_on_unparseable_target() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &dir.path().join("abyssum.db"));

    let output = std::process::Command::new(abyssum_bin())
        .arg("--config")
        .arg(&cfg)
        // A space is not a valid host character; this cannot be parsed as a URL.
        .arg("--targets")
        .arg("bad target with spaces")
        .arg("--scanners")
        .arg("cors")
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(1),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
