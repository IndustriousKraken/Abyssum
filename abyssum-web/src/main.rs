//! `abyssum-web` — the web surface binary.
//!
//! A thin wrapper: parse arguments (clap exposes `--version`/`--help`), load
//! layered configuration, initialize logging, then build the engine and serve
//! until stopped. All behavior lives in the [`abyssum_web`] library.

use std::process::ExitCode;

use abyssum_core::{logging, Config};
use clap::Parser;

/// Abyssum web surface (interactive UI with live scan progress).
#[derive(Debug, Parser)]
#[command(
    name = "abyssum-web",
    version,
    about = "Abyssum web surface (authenticated UI with live scan progress)",
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
    // clap handles `--version` / `--help` here, printing and exiting with 0
    // before any runtime is built.
    let cli = Cli::parse();

    let config = match Config::load(&cli.config) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("abyssum-web: failed to load configuration: {err}");
            return ExitCode::FAILURE;
        }
    };

    logging::init(&config);

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("abyssum-web: failed to start async runtime: {err}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(abyssum_web::serve(config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("abyssum-web: {err}");
            ExitCode::FAILURE
        }
    }
}
