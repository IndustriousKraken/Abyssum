//! The end-to-end CLI run: validate, scan, persist, render.
//!
//! [`execute`] is the whole spine behind one command. It loads and overlays
//! configuration, initializes logging, validates targets and scanner ids *before*
//! any request is issued, opens persistence, drives the selected scanners through
//! the shared [`Orchestrator`] while draining progress, stores the session and its
//! findings exactly as a web-initiated scan would, and renders the findings in the
//! requested format. The binary is a thin wrapper that prints the rendered output
//! and maps the outcome to a process exit code.

use std::sync::Arc;

use abyssum_core::{
    logging, Config, DatabaseManager, Orchestrator, ProgressCallback, ProgressKind, ProgressUpdate,
    ScanSession, ScannerRegistry, SessionStatus,
};
use abyssum_scanners::register_builtins;
use uuid::Uuid;

use crate::cli::Cli;
use crate::config_overlay::{apply_overrides, Overrides};
use crate::{render, validate};

/// Process exit code: the scan completed.
pub const EXIT_SUCCESS: u8 = 0;
/// Process exit code: invalid input (unknown scanner, unparseable target, bad
/// configuration).
pub const EXIT_BAD_INPUT: u8 = 1;
/// Process exit code: the scan failed to run (engine, persistence, or render
/// error, or no scanner could run at all).
pub const EXIT_SCAN_FAILURE: u8 = 2;
/// Process exit code: the run was interrupted (Ctrl-C / SIGINT). Follows the
/// conventional `128 + SIGINT`.
pub const EXIT_INTERRUPTED: u8 = 130;

/// A failure that aborts the run before any output is produced. Carries the exit
/// code the process should return.
#[derive(Debug)]
pub enum CliError {
    /// Invalid input — rejected before any request is issued. Exits [`EXIT_BAD_INPUT`].
    BadInput(String),
    /// The scan could not run or its results could not be stored/rendered. Exits
    /// [`EXIT_SCAN_FAILURE`].
    ScanFailure(String),
}

impl CliError {
    /// The process exit code corresponding to this failure.
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::BadInput(_) => EXIT_BAD_INPUT,
            CliError::ScanFailure(_) => EXIT_SCAN_FAILURE,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::BadInput(msg) | CliError::ScanFailure(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for CliError {}

/// The result of a completed (or interrupted) run: the final session, the rendered
/// findings ready to print, and the process exit code that reflects the outcome.
#[derive(Debug)]
pub struct RunOutcome {
    /// The final session snapshot, as persisted.
    pub session: ScanSession,
    /// The findings rendered in the requested output format (trailing newline
    /// included).
    pub rendered: String,
    /// The process exit code: `0` completed, `130` interrupted, `2` errored.
    pub exit_code: u8,
}

/// Run the CLI end to end from already-parsed arguments.
///
/// Returns [`Err`] for a failure that prevents the scan from producing output
/// (bad input, or an engine/persistence/render error); otherwise [`Ok`] with the
/// rendered findings and an exit code (`0` on completion, `130` if interrupted,
/// `2` if no scanner ran). The findings are persisted before they are rendered, so
/// a returned [`RunOutcome`] always corresponds to a stored session.
pub async fn execute(cli: Cli) -> Result<RunOutcome, CliError> {
    // 1. Configuration: defaults < file < env < CLI flags. The base reflects the
    //    first three layers; the overlay adds the CLI layer for this run only.
    let base = Config::load(&cli.config)
        .map_err(|e| CliError::BadInput(format!("failed to load configuration: {e}")))?;
    let overrides = Overrides {
        min_delay: cli.min_delay,
        max_delay: cli.max_delay,
        log_level: cli.log_level.clone(),
    };
    let config = apply_overrides(base, &overrides);

    // 2. Logging at the chosen level, before the scan starts.
    logging::init(&config);

    // 3. Validate targets up front — no request is issued for a bad selection.
    let targets =
        validate::parse_targets(&cli.targets).map_err(|e| CliError::BadInput(e.to_string()))?;

    // 4. Open persistence (creates and seeds the store on first run).
    let db = DatabaseManager::connect_from_config(&config)
        .await
        .map_err(|e| CliError::ScanFailure(format!("failed to open the result store: {e}")))?;

    // 5. Build the registry from the seeded store, then validate the requested
    //    scanner ids against its `available()` ids — still before any request.
    let config = Arc::new(config);
    let mut registry = ScannerRegistry::new(config.clone());
    register_builtins(&mut registry, &db.reference_store());
    let scanner_ids = validate::resolve_scanners(&cli.scanners, &registry.available())
        .map_err(|e| CliError::BadInput(e.to_string()))?;

    // 6. Create a session for the targets/scanners and run it through the shared
    //    engine, draining progress and honoring Ctrl-C.
    let orchestrator = Orchestrator::new(config, registry);
    let handle = orchestrator
        .create_session(targets, scanner_ids)
        .map_err(|e| CliError::BadInput(e.to_string()))?;
    let session_id = handle.lock().expect("session handle not poisoned").id;

    let session = run_to_completion(&orchestrator, session_id, progress_callback())
        .await
        .map_err(|e| CliError::ScanFailure(format!("scan failed: {e}")))?;

    // 7. Persist the session and its findings, identically to a web-initiated scan
    //    (the session row first, so the findings' foreign key resolves).
    db.save_session(&session)
        .await
        .map_err(|e| CliError::ScanFailure(format!("failed to persist the scan session: {e}")))?;
    for finding in &session.findings {
        db.save_finding(session.id, finding)
            .await
            .map_err(|e| CliError::ScanFailure(format!("failed to persist a finding: {e}")))?;
    }

    // 8. Render the findings, then map the terminal status to an exit code.
    let rendered = render::render(&session.findings, cli.output)
        .map_err(|e| CliError::ScanFailure(e.to_string()))?;
    let exit_code = match session.status {
        SessionStatus::Completed => EXIT_SUCCESS,
        SessionStatus::Cancelled => EXIT_INTERRUPTED,
        // Errored (no scanner ran) or any unexpected non-terminal status.
        _ => EXIT_SCAN_FAILURE,
    };

    Ok(RunOutcome {
        session,
        rendered,
        exit_code,
    })
}

/// Run the session to its terminal state, cancelling promptly on Ctrl-C.
///
/// On the first SIGINT the orchestrator's cancel path is signalled so the scan
/// stops promptly; the run future then resolves with the partial (`Cancelled`)
/// session, whose findings are still rendered and persisted by the caller.
async fn run_to_completion(
    orchestrator: &Orchestrator,
    session_id: Uuid,
    progress: ProgressCallback,
) -> abyssum_core::Result<ScanSession> {
    let run = orchestrator.run(session_id, Some(progress));
    tokio::pin!(run);
    loop {
        tokio::select! {
            // Bias toward completion so a run that finishes at the same time as a
            // signal is reported as completed, not interrupted.
            biased;
            result = &mut run => return result,
            signal = tokio::signal::ctrl_c() => {
                if signal.is_ok() {
                    // Best effort: a race where the run just finished leaves nothing
                    // active to cancel, which is fine.
                    let _ = orchestrator.cancel(session_id);
                }
                // Keep awaiting the run; it returns the Cancelled session promptly.
            }
        }
    }
}

/// Build the progress callback that drains updates to the terminal as the scan
/// runs. Orchestrator unit-level updates surface at `info`; the finer
/// scanner-internal probe updates at `debug`. The two are told apart by the
/// update's [`ProgressKind`] — a structural discriminator, not the wording of the
/// free-form message. Output goes through `tracing`, so it is plain log lines when
/// not attached to a TTY and its volume follows the chosen log level.
fn progress_callback() -> ProgressCallback {
    Arc::new(|update: ProgressUpdate| match update.kind {
        ProgressKind::Unit => {
            tracing::info!(
                target: "abyssum::progress",
                scanner = %update.scanner_id,
                completed = update.items_completed,
                total = update.total_items,
                item = update.current_item.as_deref().unwrap_or(""),
                "scan progress",
            );
        }
        ProgressKind::ScannerInternal => {
            tracing::debug!(
                target: "abyssum::progress",
                scanner = %update.scanner_id,
                completed = update.items_completed,
                total = update.total_items,
                item = update.current_item.as_deref().unwrap_or(""),
                "scanner progress",
            );
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_map_from_error_kind() {
        assert_eq!(CliError::BadInput("x".into()).exit_code(), EXIT_BAD_INPUT);
        assert_eq!(
            CliError::ScanFailure("x".into()).exit_code(),
            EXIT_SCAN_FAILURE
        );
        // The conventional interrupt code.
        assert_eq!(EXIT_INTERRUPTED, 130);
    }
}
