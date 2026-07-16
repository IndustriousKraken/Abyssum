//! `abyssum-cli` — the library behind the `abyssum` command-line surface.
//!
//! The binary ([`main`](../main/index.html)) is a thin shell: it parses
//! arguments and hands them to [`execute`], which wires the whole spine together
//! — argument validation, layered configuration, the orchestrator, persistence,
//! and result rendering — over the *same* `abyssum-core` engine the web surface
//! uses, so the two cannot drift.
//!
//! The pieces are split so each is unit-testable in isolation:
//!
//! - [`cli`] — the `clap` argument parser and the [`OutputFormat`] value enum.
//! - [`validate`] — target parsing (defaulting the scheme to `https`) and
//!   scanner-id resolution against the registry's `available()` ids.
//! - [`config_overlay`] — overlaying CLI flags on the loaded [`Config`], with the
//!   configured pacing floor preserved.
//! - [`render`] — the table / JSON / CSV projections of one findings set.
//! - [`report`] — [`run_report`], the `report` subcommand over stored sessions.
//! - [`diff`] — [`run_diff`], the `diff` subcommand comparing two stored sessions.
//! - [`run`] — [`execute`], the end-to-end run: validate, scan, persist, render.

pub mod cli;
pub mod config_overlay;
pub mod diff;
pub mod render;
pub mod report;
pub mod run;
pub mod validate;

pub use cli::{Cli, Command, DiffArgs, OutputFormat, ReportArgs, ReportFormat};
pub use config_overlay::{Overrides, apply_overrides};
pub use diff::run_diff;
pub use report::{ReportOutcome, run_report};
pub use run::{
    CliError, EXIT_BAD_INPUT, EXIT_INTERRUPTED, EXIT_SCAN_FAILURE, EXIT_SUCCESS, RunOutcome,
    execute,
};
