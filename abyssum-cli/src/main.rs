//! `abyssum` — the command-line surface.
//!
//! A thin shell over [`abyssum_cli`]: parse arguments (so `clap` serves `--help`
//! and `--version`), run the scan end to end through the shared engine, print the
//! rendered findings, and map the outcome to a process exit code so the CLI is
//! safe to script. All scanning, pacing, persistence, and rendering live in the
//! library and `abyssum-core`, so the CLI and web surfaces cannot drift.

use std::process::ExitCode;

use abyssum_cli::{execute, Cli};
use clap::Parser;

#[tokio::main]
async fn main() -> ExitCode {
    // clap handles `--version` / `--help` here, printing and exiting with 0.
    let cli = Cli::parse();

    match execute(cli).await {
        Ok(outcome) => {
            // The rendered findings already carry a trailing newline.
            print!("{}", outcome.rendered);
            ExitCode::from(outcome.exit_code)
        }
        Err(err) => {
            eprintln!("abyssum: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}
