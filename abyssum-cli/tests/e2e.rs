//! End-to-end CLI integration test — local only, no real targets.
//!
//! A full run is driven in-process through [`abyssum_cli::execute`] against a
//! **local mock HTTP server** (a permissive-CORS responder), then the assertions
//! prove the spec's persistence and output contracts: a session is created and
//! stored, its findings survive reopening the store, and the table / JSON / CSV
//! renderings all reflect the same findings (tasks 5.2 and 8.1).

use abyssum_cli::{execute, render, Cli, OutputFormat};
use abyssum_core::{DatabaseManager, Finding, SessionStatus};

mod common;
use common::{spawn_cors_mock, write_config};

#[tokio::test]
async fn full_run_persists_session_and_all_formats_agree() {
    let addr = spawn_cors_mock().await;
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("abyssum.db");
    let cfg_path = write_config(dir.path(), &db_path);

    let cli = Cli {
        targets: vec![format!("http://{addr}")],
        scanners: vec!["cors".to_string()],
        min_delay: None,
        max_delay: None,
        log_level: None,
        output: OutputFormat::Table,
        config: cfg_path.to_string_lossy().into_owned(),
    };

    let outcome = execute(cli).await.expect("the run should complete");

    // The scan completed and produced the mock's CORS findings.
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(outcome.session.status, SessionStatus::Completed);
    assert!(
        !outcome.session.findings.is_empty(),
        "the permissive-CORS mock should yield findings"
    );

    let session_id = outcome.session.id;
    let finding_count = outcome.session.findings.len();

    // Reopen the store to prove the session and findings survive a restart.
    let db = DatabaseManager::connect(&db_path).await.unwrap();
    let stored = db
        .get_session(session_id)
        .await
        .unwrap()
        .expect("the CLI run's session must be retrievable from persistence");
    assert_eq!(stored.status, SessionStatus::Completed);
    assert_eq!(
        stored.findings.len(),
        finding_count,
        "every finding must be retrievable after reopening the store"
    );
    // Persistence stamped each finding with a stable id.
    assert!(stored.findings.iter().all(|f| f.id.is_some()));

    // Render the stored findings in all three formats; each must reflect the same
    // set of findings.
    let table = render::render(&stored.findings, OutputFormat::Table).unwrap();
    let json = render::render(&stored.findings, OutputFormat::Json).unwrap();
    let csv = render::render(&stored.findings, OutputFormat::Csv).unwrap();

    // JSON: parses back to exactly the stored findings.
    let from_json: Vec<Finding> = serde_json::from_str(&json).unwrap();
    assert_eq!(from_json, stored.findings);

    // CSV: a header row plus one record per finding (the CORS titles are
    // single-line, so a line count is exact here).
    assert_eq!(
        csv.lines().next().unwrap(),
        "Scanner,Target,Status,Severity,Title"
    );
    assert_eq!(csv.lines().count(), finding_count + 1);

    // Table: header + separator + one row per finding.
    assert_eq!(table.lines().count(), finding_count + 2);

    // Every stored finding is represented, by title, in every textual format.
    for finding in &stored.findings {
        assert!(
            table.contains(&finding.title),
            "table missing {:?}",
            finding.title
        );
        assert!(
            csv.contains(&finding.title),
            "csv missing {:?}",
            finding.title
        );
        assert!(
            json.contains(&finding.title),
            "json missing {:?}",
            finding.title
        );
    }
    // All formats agree on the target as well.
    let target_url = format!("http://{addr}/");
    assert!(table.contains(&target_url));
    assert!(csv.contains(&target_url));
}
