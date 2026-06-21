//! `abyssum` — the command-line surface.
//!
//! For the bootstrap change this only proves the workspace builds and links end
//! to end: it parses arguments (exposing `--version` and `--help`), loads
//! configuration, initializes logging, and exits cleanly. Scanner subcommands
//! arrive in later changes (c01 onward).

use std::process::ExitCode;

use abyssum_core::{logging, Config};
use clap::Parser;

/// Abyssum: a patient, stealthy API vulnerability scanner for **authorized**
/// security testing only.
#[derive(Debug, Parser)]
#[command(
    name = "abyssum",
    version,
    about = "Abyssum — API vulnerability scanner for authorized testing",
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
            eprintln!("abyssum: failed to load configuration: {err}");
            return ExitCode::FAILURE;
        }
    };

    logging::init(&config);
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "abyssum CLI ready");

    println!(
        "abyssum {} — no scanners wired yet (subcommands arrive in later changes)",
        env!("CARGO_PKG_VERSION")
    );

    ExitCode::SUCCESS
}
