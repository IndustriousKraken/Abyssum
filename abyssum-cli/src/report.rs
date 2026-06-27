//! The `report` subcommand: render stored sessions through the shared engine.
//!
//! [`run_report`] is a thin shell over [`abyssum_core::ReportGenerator`]: it loads
//! configuration to find the result store, parses the requested session ids,
//! generates the report in the chosen format, and either writes it to a file or
//! returns it for the binary to print. An unknown session id is rejected as bad
//! input (a non-zero exit) before anything is written.

use abyssum_core::{
    Config, DatabaseManager, Error, ReportFormat as CoreFormat, ReportGenerator, ReportOptions,
};
use uuid::Uuid;

use crate::cli::{ReportArgs, ReportFormat};
use crate::run::{CliError, EXIT_SUCCESS};

/// The result of a report run: the text to print (empty when written to a file)
/// and the process exit code.
#[derive(Debug)]
pub struct ReportOutcome {
    /// The rendered report ready to print, or empty when `--output` wrote a file.
    pub rendered: String,
    /// The process exit code (`0` on success).
    pub exit_code: u8,
}

/// Generate a report from already-parsed `report` arguments.
pub async fn run_report(args: ReportArgs) -> Result<ReportOutcome, CliError> {
    let config = Config::load(&args.config)
        .map_err(|e| CliError::BadInput(format!("failed to load configuration: {e}")))?;

    // Parse the session ids up front so a malformed id never opens the store.
    let mut session_ids = Vec::with_capacity(args.sessions.len());
    for raw in &args.sessions {
        let id = Uuid::parse_str(raw)
            .map_err(|_| CliError::BadInput(format!("invalid session id: {raw}")))?;
        session_ids.push(id);
    }

    let db = DatabaseManager::connect_from_config(&config)
        .await
        .map_err(|e| CliError::ScanFailure(format!("failed to open the result store: {e}")))?;

    let options = ReportOptions {
        include_evidence: !args.no_evidence,
    };
    let report = ReportGenerator::new(db)
        .generate(&session_ids, core_format(args.format), options)
        .await
        .map_err(map_report_error)?;

    match &args.output {
        Some(path) => {
            std::fs::write(path, &report).map_err(|e| {
                CliError::ScanFailure(format!("failed to write report to {path}: {e}"))
            })?;
            Ok(ReportOutcome {
                rendered: String::new(),
                exit_code: EXIT_SUCCESS,
            })
        }
        None => Ok(ReportOutcome {
            rendered: ensure_trailing_newline(report),
            exit_code: EXIT_SUCCESS,
        }),
    }
}

/// Map the CLI's report format onto the core generator's.
fn core_format(format: ReportFormat) -> CoreFormat {
    match format {
        ReportFormat::Markdown => CoreFormat::Markdown,
        ReportFormat::Json => CoreFormat::Json,
        ReportFormat::Csv => CoreFormat::Csv,
        ReportFormat::Hackerone => CoreFormat::HackerOne,
    }
}

/// Map a report generation error to a CLI failure. An unknown session id is bad
/// input (exit `1`); anything else (e.g. a session with nothing to report) is a
/// run failure (exit `2`).
fn map_report_error(err: Error) -> CliError {
    match err {
        Error::NotFound(msg) => CliError::BadInput(msg),
        other => CliError::ScanFailure(other.to_string()),
    }
}

/// Ensure the printed report ends with exactly one trailing newline.
fn ensure_trailing_newline(mut report: String) -> String {
    if !report.ends_with('\n') {
        report.push('\n');
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_session_maps_to_bad_input() {
        let err = map_report_error(Error::NotFound("no session".into()));
        assert!(matches!(err, CliError::BadInput(_)));
    }

    #[test]
    fn nothing_to_report_maps_to_scan_failure() {
        let err = map_report_error(Error::Other("nothing to report".into()));
        assert!(matches!(err, CliError::ScanFailure(_)));
    }

    #[test]
    fn trailing_newline_is_idempotent() {
        assert_eq!(ensure_trailing_newline("x".into()), "x\n");
        assert_eq!(ensure_trailing_newline("x\n".into()), "x\n");
    }
}
