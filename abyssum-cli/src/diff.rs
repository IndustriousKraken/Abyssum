//! The `diff` subcommand: compare two stored sessions through the shared engine.
//!
//! [`run_diff`] is a thin shell over [`abyssum_core::diff_sessions`]: it loads
//! configuration to find the result store, parses the two session ids, loads both
//! sessions, computes the diff, and renders it in the chosen format. An unknown (or
//! malformed) session id is rejected as bad input — a non-zero exit — and no diff is
//! produced.

use abyssum_core::{diff_sessions, Config, DatabaseManager, ScanSession};
use uuid::Uuid;

use crate::cli::{DiffArgs, OutputFormat};
use crate::report::ReportOutcome;
use crate::run::{CliError, EXIT_SUCCESS};

/// Diff two stored sessions from already-parsed `diff` arguments.
pub async fn run_diff(args: DiffArgs) -> Result<ReportOutcome, CliError> {
    let config = Config::load(&args.config)
        .map_err(|e| CliError::BadInput(format!("failed to load configuration: {e}")))?;

    // Parse both ids up front so a malformed id never opens the store.
    let older = parse_session_id(&args.older)?;
    let newer = parse_session_id(&args.newer)?;

    let db = DatabaseManager::connect_from_config(&config)
        .await
        .map_err(|e| CliError::ScanFailure(format!("failed to open the result store: {e}")))?;

    let older_session = load_session(&db, older).await?;
    let newer_session = load_session(&db, newer).await?;

    let diff = diff_sessions(&older_session, &newer_session);
    let rendered = match args.output {
        OutputFormat::Table => diff.render_table(),
        OutputFormat::Json => diff
            .render_json()
            .map_err(|e| CliError::ScanFailure(e.to_string()))?,
        OutputFormat::Csv => diff.render_csv(),
    };

    Ok(ReportOutcome {
        rendered,
        exit_code: EXIT_SUCCESS,
    })
}

/// Parse a session id, rejecting a malformed one as bad input.
fn parse_session_id(raw: &str) -> Result<Uuid, CliError> {
    Uuid::parse_str(raw).map_err(|_| CliError::BadInput(format!("invalid session id: {raw}")))
}

/// Load one session, mapping an absent id to bad input (so a diff against an
/// unknown session produces no output and a non-zero exit).
async fn load_session(db: &DatabaseManager, id: Uuid) -> Result<ScanSession, CliError> {
    db.get_session(id)
        .await
        .map_err(|e| CliError::ScanFailure(format!("failed to read session {id}: {e}")))?
        .ok_or_else(|| CliError::BadInput(format!("no scan session with id {id}")))
}
