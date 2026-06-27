//! Integration tests for the `report` subcommand surface — local only, no network.
//!
//! These drive [`abyssum_cli::run_report`] against a temp store seeded with a
//! session, proving the command renders a chosen format to stdout or a file and
//! rejects an unknown session id with a non-zero exit (tasks 7.1 / 7.2).

use abyssum_cli::{run_report, CliError, ReportArgs, ReportFormat, EXIT_SUCCESS};
use abyssum_core::{
    DatabaseManager, Finding, ScanSession, SessionStatus, Severity, Status, Target,
};
use uuid::Uuid;

mod common;
use common::write_config;

/// Seed a store at `db_path` with one completed session and return its id.
async fn seed(db_path: &std::path::Path) -> Uuid {
    let db = DatabaseManager::connect(db_path).await.unwrap();
    let mut session = ScanSession::new(
        vec![Target::parse("https://api.example.com").unwrap()],
        vec!["cors".into()],
    );
    session.status = SessionStatus::Completed;
    let id = session.id;
    session.findings = vec![Finding::builder(
        "cors",
        Target::parse("https://api.example.com").unwrap(),
        "Permissive CORS",
    )
    .severity(Severity::High)
    .status(Status::Vulnerable)
    .build()];
    db.save_session(&session).await.unwrap();
    for finding in &session.findings {
        db.save_finding(id, finding).await.unwrap();
    }
    id
}

fn args(sessions: Vec<String>, format: ReportFormat, config: String) -> ReportArgs {
    ReportArgs {
        sessions,
        format,
        output: None,
        no_evidence: false,
        config,
    }
}

#[tokio::test]
async fn report_renders_markdown_to_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("abyssum.db");
    let cfg = write_config(dir.path(), &db_path);
    let id = seed(&db_path).await;

    let outcome = run_report(args(
        vec![id.to_string()],
        ReportFormat::Markdown,
        cfg.to_string_lossy().into_owned(),
    ))
    .await
    .expect("the report should generate");

    assert_eq!(outcome.exit_code, EXIT_SUCCESS);
    assert!(outcome.rendered.contains("# Abyssum Scan Report"));
    assert!(outcome.rendered.contains("Permissive CORS"));
}

#[tokio::test]
async fn report_writes_to_a_file_when_output_is_set() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("abyssum.db");
    let cfg = write_config(dir.path(), &db_path);
    let id = seed(&db_path).await;
    let out_path = dir.path().join("report.md");

    let mut args = args(
        vec![id.to_string()],
        ReportFormat::Markdown,
        cfg.to_string_lossy().into_owned(),
    );
    args.output = Some(out_path.to_string_lossy().into_owned());

    let outcome = run_report(args).await.expect("the report should generate");
    assert_eq!(outcome.exit_code, EXIT_SUCCESS);
    assert!(outcome.rendered.is_empty(), "file output prints nothing");

    let written = std::fs::read_to_string(&out_path).unwrap();
    assert!(written.contains("Permissive CORS"));
}

#[tokio::test]
async fn report_rejects_an_unknown_session() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("abyssum.db");
    let cfg = write_config(dir.path(), &db_path);
    seed(&db_path).await; // a real store, but we ask for a different id

    let err = run_report(args(
        vec![Uuid::new_v4().to_string()],
        ReportFormat::Markdown,
        cfg.to_string_lossy().into_owned(),
    ))
    .await
    .expect_err("an unknown session must be rejected");

    // Bad input → a non-zero exit code, and nothing is written.
    assert!(matches!(err, CliError::BadInput(_)), "got {err:?}");
    assert_ne!(err.exit_code(), EXIT_SUCCESS);
}

#[tokio::test]
async fn report_rejects_a_malformed_session_id() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("abyssum.db");
    let cfg = write_config(dir.path(), &db_path);

    let err = run_report(args(
        vec!["not-a-uuid".to_string()],
        ReportFormat::Csv,
        cfg.to_string_lossy().into_owned(),
    ))
    .await
    .expect_err("a malformed id must be rejected");
    assert!(matches!(err, CliError::BadInput(_)), "got {err:?}");
}
