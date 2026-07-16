//! Integration tests for the `diff` subcommand surface — local only, no network.
//!
//! These drive [`abyssum_cli::run_diff`] against a temp store seeded with two
//! sessions, proving the command reports added / resolved / changed findings, and
//! rejects an unknown session id with a non-zero exit (tasks 1 / 5).

use abyssum_cli::{run_diff, CliError, DiffArgs, OutputFormat, EXIT_SUCCESS};
use abyssum_core::{
    DatabaseManager, Finding, ScanSession, SessionStatus, Severity, Status, Target,
};
use uuid::Uuid;

mod common;
use common::write_config;

fn finding(scanner: &str, url: &str, title: &str, sev: Severity, status: Status) -> Finding {
    Finding::builder(scanner, Target::parse(url).unwrap(), title)
        .severity(sev)
        .status(status)
        .build()
}

/// Persist a completed session carrying `findings`, returning its id.
async fn seed(db: &DatabaseManager, findings: Vec<Finding>) -> Uuid {
    let mut session = ScanSession::new(
        vec![Target::parse("https://api.example.com").unwrap()],
        vec!["cors".into()],
    );
    session.status = SessionStatus::Completed;
    session.findings = findings;
    let id = session.id;
    db.save_session(&session).await.unwrap();
    for f in &session.findings {
        db.save_finding(id, f).await.unwrap();
    }
    id
}

fn args(older: Uuid, newer: Uuid, output: OutputFormat, config: String) -> DiffArgs {
    DiffArgs {
        older: older.to_string(),
        newer: newer.to_string(),
        output,
        config,
    }
}

#[tokio::test]
async fn diff_reports_added_resolved_and_changed() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("abyssum.db");
    let cfg = write_config(dir.path(), &db_path);
    let db = DatabaseManager::connect(&db_path).await.unwrap();

    let older = seed(
        &db,
        vec![
            finding(
                "bac",
                "https://api.example.com/admin",
                "Admin open",
                Severity::High,
                Status::Vulnerable,
            ),
            finding(
                "idor",
                "https://api.example.com/u/1",
                "Enumerable",
                Severity::Low,
                Status::Safe,
            ),
        ],
    )
    .await;
    let newer = seed(
        &db,
        vec![
            finding(
                "rest_discovery",
                "https://api.example.com/debug",
                "Debug route",
                Severity::Medium,
                Status::Vulnerable,
            ),
            finding(
                "idor",
                "https://api.example.com/u/1",
                "Enumerable",
                Severity::High,
                Status::Vulnerable,
            ),
        ],
    )
    .await;

    let outcome = run_diff(args(
        older,
        newer,
        OutputFormat::Json,
        cfg.to_string_lossy().into_owned(),
    ))
    .await
    .expect("the diff should generate");
    assert_eq!(outcome.exit_code, EXIT_SUCCESS);

    let value: serde_json::Value = serde_json::from_str(&outcome.rendered).unwrap();
    assert_eq!(value["added"].as_array().unwrap().len(), 1);
    assert_eq!(value["added"][0]["title"], "Debug route");
    assert_eq!(value["resolved"].as_array().unwrap().len(), 1);
    assert_eq!(value["resolved"][0]["title"], "Admin open");
    assert_eq!(value["changed"].as_array().unwrap().len(), 1);
    assert_eq!(value["changed"][0]["old_severity"], "low");
    assert_eq!(value["changed"][0]["new_severity"], "high");
    assert_eq!(value["unchanged"], 0);
}

#[tokio::test]
async fn diff_rejects_an_unknown_session() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("abyssum.db");
    let cfg = write_config(dir.path(), &db_path);
    let db = DatabaseManager::connect(&db_path).await.unwrap();
    let known = seed(&db, vec![]).await;

    let err = run_diff(args(
        known,
        Uuid::new_v4(), // no such session
        OutputFormat::Table,
        cfg.to_string_lossy().into_owned(),
    ))
    .await
    .expect_err("an unknown session must be rejected");
    assert!(matches!(err, CliError::BadInput(_)), "got {err:?}");
    assert_ne!(err.exit_code(), EXIT_SUCCESS);
}
