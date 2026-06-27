//! `abyssum` — the command-line surface.
//!
//! A thin shell over [`abyssum_cli`]: parse arguments (so `clap` serves `--help`
//! and `--version`), run the scan end to end through the shared engine, print the
//! rendered findings, and map the outcome to a process exit code so the CLI is
//! safe to script. All scanning, pacing, persistence, and rendering live in the
//! library and `abyssum-core`, so the CLI and web surfaces cannot drift.

use std::process::ExitCode;

use abyssum_cli::{execute, run_report, Cli, Command};
use clap::Parser;

#[tokio::main]
async fn main() -> ExitCode {
    // clap handles `--version` / `--help` here, printing and exiting with 0.
    let mut cli = Cli::parse();

    // Branch on the subcommand: `report` renders stored sessions, anything else
    // (the default) runs a scan. Both paths yield a (rendered, exit_code) pair.
    let result = match cli.command.take() {
        Some(Command::Report(args)) => run_report(args).await.map(|o| (o.rendered, o.exit_code)),
        None => execute(cli).await.map(|o| (o.rendered, o.exit_code)),
    };

    match result {
        Ok((rendered, exit_code)) => {
            // The rendered output already carries a trailing newline.
            print!("{rendered}");
            ExitCode::from(exit_code)
        }
        Err(err) => {
            eprintln!("abyssum: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}
