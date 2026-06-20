//! Smoke tests for the `abyssum-web` binary: it must run `--version` and
//! `--help` and exit 0. Cargo provides the built binary's path via
//! `CARGO_BIN_EXE_*`.

use std::process::Command;

fn abyssum_web() -> Command {
    Command::new(env!("CARGO_BIN_EXE_abyssum-web"))
}

#[test]
fn version_flag_prints_version_and_exits_zero() {
    let output = abyssum_web()
        .arg("--version")
        .output()
        .expect("failed to run `abyssum-web --version`");

    assert!(
        output.status.success(),
        "exit status was {:?}",
        output.status.code()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("2.0.0"),
        "version output did not contain the crate version: {stdout:?}"
    );
}

#[test]
fn help_flag_prints_usage_and_exits_zero() {
    let output = abyssum_web()
        .arg("--help")
        .output()
        .expect("failed to run `abyssum-web --help`");

    assert!(
        output.status.success(),
        "exit status was {:?}",
        output.status.code()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.to_lowercase().contains("usage"),
        "help output did not contain usage information: {stdout:?}"
    );
}
