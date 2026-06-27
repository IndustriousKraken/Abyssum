//! Integration tests for the `report-generation` capability.
//!
//! These exercise the DB-backed path: [`ReportGenerator`] loads a session and its
//! findings through the real persistence layer (a temporary on-disk SQLite file)
//! and renders them. The format-by-format rendering details are unit-tested in the
//! `report` module against in-memory fixtures; here we prove the store wiring, the
//! not-found error, and a multi-session export read back from storage. No network,
//! no real targets.

use abyssum_core::{
    DatabaseManager, Finding, ReportFormat, ReportGenerator, ReportOptions, ScanSession,
    SessionStatus, Severity, Status, Target,
};
use uuid::Uuid;

async fn fresh_store() -> (DatabaseManager, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("abyssum.db");
    let db = DatabaseManager::connect(&path).await.unwrap();
    (db, dir)
}

fn target(url: &str) -> Target {
    Target::parse(url).unwrap()
}

/// Store a completed session whose findings mix reportable and benign results.
async fn store_session(db: &DatabaseManager, target_url: &str) -> Uuid {
    let mut session = ScanSession::new(vec![target(target_url)], vec!["cors".into(), "bac".into()]);
    session.status = SessionStatus::Completed;
    let id = session.id;
    session.findings = vec![
        Finding::builder(
            "bac",
            target(target_url).with_path("/admin"),
            "Admin reachable",
        )
        .severity(Severity::Critical)
        .status(Status::Vulnerable)
        .description("Admin panel responds without auth")
        .evidence(serde_json::json!({ "method": "GET", "status": 200 }))
        .build(),
        Finding::builder("cors", target(target_url), "Permissive CORS")
            .severity(Severity::High)
            .status(Status::Vulnerable)
            .build(),
        // Benign: must never appear in any report.
        Finding::builder("cors", target(target_url), "CORS locked down")
            .status(Status::Safe)
            .build(),
    ];

    db.save_session(&session).await.unwrap();
    for finding in &session.findings {
        db.save_finding(id, finding).await.unwrap();
    }
    id
}

#[tokio::test]
async fn markdown_report_is_built_from_the_store() {
    let (db, _dir) = fresh_store().await;
    let id = store_session(&db, "https://api.example.com").await;

    let md = ReportGenerator::new(db)
        .generate(&[id], ReportFormat::Markdown, ReportOptions::default())
        .await
        .unwrap();

    assert!(md.contains("https://api.example.com"));
    assert!(md.contains(&id.to_string()));
    assert!(
        md.contains("Total findings: 2"),
        "only the two reportable findings"
    );
    assert!(md.contains("Admin reachable"));
    assert!(md.contains("Permissive CORS"));
    assert!(
        !md.contains("CORS locked down"),
        "benign result leaked into the report"
    );
}

#[tokio::test]
async fn json_export_reads_multiple_sessions_from_the_store() {
    let (db, _dir) = fresh_store().await;
    let a = store_session(&db, "https://a.example.com").await;
    let b = store_session(&db, "https://b.example.com").await;

    let json = ReportGenerator::new(db)
        .generate(&[a, b], ReportFormat::Json, ReportOptions::default())
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_eq!(value["session_count"], 2);
    let sessions = value["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2);
    // Each stored session contributes only its two reportable findings.
    assert_eq!(sessions[0]["findings"].as_array().unwrap().len(), 2);
    assert_eq!(sessions[1]["findings"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn unknown_session_is_a_not_found_error() {
    let (db, _dir) = fresh_store().await;
    let missing = Uuid::new_v4();

    let err = ReportGenerator::new(db)
        .generate(&[missing], ReportFormat::Markdown, ReportOptions::default())
        .await
        .unwrap_err();

    assert!(
        matches!(err, abyssum_core::Error::NotFound(_)),
        "expected a not-found error, got {err:?}"
    );
}

#[tokio::test]
async fn hackerone_errors_when_a_stored_session_has_no_reportable_findings() {
    let (db, _dir) = fresh_store().await;
    let mut session = ScanSession::new(vec![target("https://x.example.com")], vec!["cors".into()]);
    let id = session.id;
    session.findings = vec![
        Finding::builder("cors", target("https://x.example.com"), "Safe")
            .status(Status::Safe)
            .build(),
    ];
    db.save_session(&session).await.unwrap();
    for finding in &session.findings {
        db.save_finding(id, finding).await.unwrap();
    }

    let err = ReportGenerator::new(db)
        .generate(&[id], ReportFormat::HackerOne, ReportOptions::default())
        .await
        .unwrap_err();
    assert!(matches!(err, abyssum_core::Error::Other(_)), "got {err:?}");
}
