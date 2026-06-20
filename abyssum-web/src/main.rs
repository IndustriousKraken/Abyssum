//! `abyssum-web` — the web surface.
//!
//! For the bootstrap change this only proves the workspace builds and links end
//! to end: it parses arguments (exposing `--version` and `--help`), loads
//! configuration, initializes logging, prints a startup line reporting where it
//! *would* bind, and exits cleanly. The axum server arrives in a later change.

use std::process::ExitCode;

use abyssum_core::{logging, Config};
use clap::Parser;

/// Abyssum web surface (interactive UI with live scan progress).
#[derive(Debug, Parser)]
#[command(
    name = "abyssum-web",
    version,
    about = "Abyssum web surface (server not implemented yet)",
    long_about = None
)]
struct Cli {
    /// Path to the YAML configuration file (missing file ⇒ built-in defaults).
    #[arg(
        long,
        value_name = "PATH",
        env = "ABYSSUM_CONFIG",
        default_value = "abyssum.yaml"
    )]
    config: String,
}

fn main() -> ExitCode {
    // clap handles `--version` / `--help` here, printing and exiting with 0.
    let cli = Cli::parse();

    let config = match Config::load(&cli.config) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("abyssum-web: failed to load configuration: {err}");
            return ExitCode::FAILURE;
        }
    };

    logging::init(&config);
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        host = %config.server.host,
        port = config.server.port,
        "abyssum-web starting"
    );

    println!(
        "abyssum-web {} ready — would bind {}:{} (server not implemented yet)",
        env!("CARGO_PKG_VERSION"),
        config.server.host,
        config.server.port
    );

    ExitCode::SUCCESS
}
