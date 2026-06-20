//! Result-persistence integration tests — local only, no network, no real
//! targets.
//!
//! Every test runs against a temporary on-disk SQLite file in a temp dir, so the
//! "reopen the store" tests genuinely exercise restart survival. They cover the
//! task list directly: restart survival (7.1), finding-field integrity (7.2),
//! every filter and combinations (7.3), migration idempotency (7.4), and atomic
//! deletion (7.5), plus session upsert, paging, summary counts, and lossless
//! evidence/target round-trips.

use std::collections::BTreeMap;
use std::path::PathBuf;

use abyssum_core::{
    DatabaseManager, Finding, FindingFilter, SessionRecord, SessionStatus, Severity, Status, Target,
};
use chrono::{DateTime, Utc};
use tempfile::TempDir;
use uuid::Uuid;

/// A temp dir plus the path to a fresh db file inside it. The dir is returned so
/// the caller keeps it alive (dropping it deletes the file).
fn temp_db_path() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("abyssum.db");
    (dir, path)
}

/// Open a manager on a brand-new temp file.
async fn open_temp() -> (TempDir, PathBuf, DatabaseManager) {
    let (dir, path) = temp_db_path();
    let db = DatabaseManager::open(&path).await.unwrap();
    (dir, path, db)
}

/// A fixed UTC timestamp `secs` seconds past a stable epoch, with no sub-second
/// part so it round-trips through the store exactly.
fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap()
}

/// A representative session record with every stored field populated.
fn session_record(id: Uuid, status: SessionStatus) -> SessionRecord {
    SessionRecord {
        session_id: id,
        status,
        targets: vec![
            Target::parse("https://api.example.com")
                .unwrap()
                .with_path("/v1"),
            Target::parse("https://b.example.com")
                .unwrap()
                .with_id_template("/users/{id}"),
        ],
        scanner_ids: vec!["rest_discovery".to_string(), "cors".to_string()],
        start_time: Some(ts(10)),
        end_time: Some(ts(20)),
        total_requests: 42,
        error_count: 3,
    }
}

/// Build a finding with all fields populated.
fn finding(
    scanner: &str,
    target: Target,
    status: Status,
    severity: Severity,
    title: &str,
    when: DateTime<Utc>,
) -> Finding {
    Finding::builder(scanner, target, title)
        .status(status)
        .severity(severity)
        .description(format!("{title} — details"))
        .recommendations("apply remediation")
        .evidence(serde_json::json!({ "request": "GET /", "status": 200 }))
        .timestamp(when)
        .build()
}

// --- 7.1 Restart survival -----------------------------------------------------

#[tokio::test]
async fn session_and_findings_survive_a_restart() {
    let (_dir, path) = temp_db_path();
    let id = Uuid::new_v4();
    let target = Target::parse("https://a.example.com").unwrap();

    // Write, then fully close the pool to simulate a process exit.
    {
        let db = DatabaseManager::open(&path).await.unwrap();
        db.upsert_session(&session_record(id, SessionStatus::Completed))
            .await
            .unwrap();
        db.save_finding(
            id,
            &finding(
                "rest_discovery",
                target.clone(),
                Status::Vulnerable,
                Severity::High,
                "First",
                ts(100),
            ),
        )
        .await
        .unwrap();
        db.save_finding(
            id,
            &finding(
                "cors",
                target,
                Status::Info,
                Severity::Info,
                "Second",
                ts(200),
            ),
        )
        .await
        .unwrap();
        db.close().await;
    }

    // Reopen the same file and assert everything reads back unchanged.
    let db = DatabaseManager::open(&path).await.unwrap();
    let stored = db.get_session(id).await.unwrap().expect("session present");
    assert_eq!(stored.record, session_record(id, SessionStatus::Completed));

    let findings = db.findings_for_session(id).await.unwrap();
    assert_eq!(findings.len(), 2);
    // Ordered oldest-first by timestamp.
    assert_eq!(findings[0].finding.title, "First");
    assert_eq!(findings[1].finding.title, "Second");
}

// --- 7.2 Finding-field integrity ---------------------------------------------

#[tokio::test]
async fn finding_keeps_every_field_and_id_across_restart() {
    let (_dir, path) = temp_db_path();
    let id = Uuid::new_v4();
    let target = Target::parse("https://api.example.com")
        .unwrap()
        .with_path("/orders")
        .with_id_template("/orders/{order_id}");

    let saved;
    {
        let db = DatabaseManager::open(&path).await.unwrap();
        db.upsert_session(&session_record(id, SessionStatus::Completed))
            .await
            .unwrap();
        let f = finding(
            "idor",
            target,
            Status::Vulnerable,
            Severity::Critical,
            "IDOR on orders",
            ts(500),
        );
        saved = db.save_finding(id, &f).await.unwrap();
        // The save assigns a stable public finding_id and the row id.
        assert!(saved.finding.id.is_some());
        db.close().await;
    }

    let db = DatabaseManager::open(&path).await.unwrap();
    let read = db.findings_for_session(id).await.unwrap();
    assert_eq!(read.len(), 1);
    let got = &read[0];

    // The public finding_id is stable across save and restart.
    assert_eq!(got.finding_id, saved.finding_id);
    // Every canonical field survives unchanged (this also covers the lossless
    // target + evidence round-trip, task 4.3).
    assert_eq!(got.finding, saved.finding);
    assert_eq!(got.finding.scanner_id, "idor");
    assert_eq!(got.finding.status, Status::Vulnerable);
    assert_eq!(got.finding.severity, Severity::Critical);
    assert_eq!(got.finding.title, "IDOR on orders");
    assert_eq!(
        got.finding.description.as_deref(),
        Some("IDOR on orders — details")
    );
    assert_eq!(
        got.finding.recommendations.as_deref(),
        Some("apply remediation")
    );
    assert_eq!(got.finding.evidence.as_ref().unwrap()["status"], 200);
    assert_eq!(got.finding.target.id_template(), Some("/orders/{order_id}"));
}

#[tokio::test]
async fn evidence_and_target_round_trip_without_loss() {
    let (_dir, _path, db) = open_temp().await;
    let id = Uuid::new_v4();
    db.upsert_session(&session_record(id, SessionStatus::Running))
        .await
        .unwrap();

    let target = Target::parse("https://deep.example.com:8443")
        .unwrap()
        .with_path("/a/b/c")
        .with_id_template("/a/b/{id}/c");
    let evidence = serde_json::json!({
        "nested": { "array": [1, 2, 3], "flag": true },
        "unicode": "café—ü",
        "null": null,
    });
    let f = Finding::builder("graphql", target.clone(), "Complex evidence")
        .evidence(evidence.clone())
        .build();
    db.save_finding(id, &f).await.unwrap();

    let read = db.findings_for_session(id).await.unwrap();
    assert_eq!(read.len(), 1);
    assert_eq!(read[0].finding.target, target);
    assert_eq!(read[0].finding.evidence.as_ref().unwrap(), &evidence);
}

// --- 3.x Session upsert / fetch / paging --------------------------------------

#[tokio::test]
async fn re_storing_a_session_updates_in_place() {
    let (_dir, _path, db) = open_temp().await;
    let id = Uuid::new_v4();

    db.upsert_session(&session_record(id, SessionStatus::Pending))
        .await
        .unwrap();
    let first = db.get_session(id).await.unwrap().unwrap();

    // Advance the session and re-store under the same id.
    let mut advanced = session_record(id, SessionStatus::Completed);
    advanced.total_requests = 999;
    advanced.error_count = 7;
    advanced.end_time = Some(ts(300));
    db.upsert_session(&advanced).await.unwrap();

    // Exactly one row, updated to the latest values.
    let all = db.list_sessions(100, 0).await.unwrap();
    assert_eq!(all.len(), 1);
    let updated = db.get_session(id).await.unwrap().unwrap();
    assert_eq!(updated.record, advanced);
    assert_eq!(updated.record.status, SessionStatus::Completed);
    // created_at is preserved; updated_at advances (or stays equal).
    assert_eq!(updated.created_at, first.created_at);
    assert!(updated.updated_at >= first.updated_at);
}

#[tokio::test]
async fn get_session_is_none_for_unknown_id() {
    let (_dir, _path, db) = open_temp().await;
    assert!(db.get_session(Uuid::new_v4()).await.unwrap().is_none());
}

#[tokio::test]
async fn list_sessions_is_newest_first_with_paging() {
    let (_dir, _path, db) = open_temp().await;
    let mut ids = Vec::new();
    for _ in 0..3 {
        let id = Uuid::new_v4();
        db.upsert_session(&session_record(id, SessionStatus::Completed))
            .await
            .unwrap();
        ids.push(id);
    }

    // Newest-first: the last inserted comes first.
    let page = db.list_sessions(2, 0).await.unwrap();
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].record.session_id, ids[2]);
    assert_eq!(page[1].record.session_id, ids[1]);

    // Offset paging continues from where the page left off.
    let page2 = db.list_sessions(2, 2).await.unwrap();
    assert_eq!(page2.len(), 1);
    assert_eq!(page2[0].record.session_id, ids[0]);
}

#[tokio::test]
async fn get_session_with_findings_bundles_them() {
    let (_dir, _path, db) = open_temp().await;
    let id = Uuid::new_v4();
    db.upsert_session(&session_record(id, SessionStatus::Completed))
        .await
        .unwrap();
    let target = Target::parse("https://a.example.com").unwrap();
    db.save_finding(
        id,
        &finding("cors", target, Status::Safe, Severity::Low, "ok", ts(1)),
    )
    .await
    .unwrap();

    let bundle = db.get_session_with_findings(id).await.unwrap().unwrap();
    assert_eq!(bundle.session.record.session_id, id);
    assert_eq!(bundle.findings.len(), 1);
    assert!(db
        .get_session_with_findings(Uuid::new_v4())
        .await
        .unwrap()
        .is_none());
}

// --- 7.3 Filters --------------------------------------------------------------

/// Seed one session with a fixed spread of findings used by the filter tests.
async fn seed_filter_fixture(db: &DatabaseManager) -> Uuid {
    let id = Uuid::new_v4();
    db.upsert_session(&session_record(id, SessionStatus::Completed))
        .await
        .unwrap();

    let ta = Target::parse("https://a.example.com").unwrap();
    let tb = Target::parse("https://b.example.com")
        .unwrap()
        .with_path("/users");

    let rows = [
        (
            "rest_discovery",
            ta.clone(),
            Status::Vulnerable,
            Severity::High,
            "SQL injection in login",
            100,
        ),
        (
            "cors",
            ta.clone(),
            Status::Safe,
            Severity::Low,
            "CORS configured correctly",
            200,
        ),
        (
            "rest_discovery",
            tb.clone(),
            Status::Info,
            Severity::Info,
            "Endpoint discovered",
            300,
        ),
        (
            "idor",
            tb.clone(),
            Status::Vulnerable,
            Severity::Critical,
            "IDOR on users",
            400,
        ),
        (
            "cors",
            ta.clone(),
            Status::Vulnerable,
            Severity::Medium,
            "Permissive CORS origin",
            500,
        ),
    ];
    for (scanner, target, status, severity, title, secs) in rows {
        db.save_finding(
            id,
            &finding(scanner, target, status, severity, title, ts(secs)),
        )
        .await
        .unwrap();
    }
    id
}

/// Collect the titles of a result set into a sorted Vec for order-independent
/// comparison.
fn titles(findings: &[abyssum_core::StoredFinding]) -> Vec<String> {
    let mut t: Vec<String> = findings.iter().map(|f| f.finding.title.clone()).collect();
    t.sort();
    t
}

#[tokio::test]
async fn filter_by_status() {
    let (_dir, _path, db) = open_temp().await;
    let id = seed_filter_fixture(&db).await;
    let got = db
        .search_findings(&FindingFilter::new().session(id).status(Status::Vulnerable))
        .await
        .unwrap();
    assert_eq!(
        titles(&got),
        [
            "IDOR on users",
            "Permissive CORS origin",
            "SQL injection in login"
        ]
    );
}

#[tokio::test]
async fn filter_by_severity() {
    let (_dir, _path, db) = open_temp().await;
    let id = seed_filter_fixture(&db).await;
    let got = db
        .search_findings(
            &FindingFilter::new()
                .session(id)
                .severity(Severity::Critical),
        )
        .await
        .unwrap();
    assert_eq!(titles(&got), ["IDOR on users"]);
}

#[tokio::test]
async fn filter_by_scanner_id() {
    let (_dir, _path, db) = open_temp().await;
    let id = seed_filter_fixture(&db).await;
    let got = db
        .search_findings(
            &FindingFilter::new()
                .session(id)
                .scanner_id("rest_discovery"),
        )
        .await
        .unwrap();
    assert_eq!(
        titles(&got),
        ["Endpoint discovered", "SQL injection in login"]
    );
}

#[tokio::test]
async fn filter_by_target() {
    let (_dir, _path, db) = open_temp().await;
    let id = seed_filter_fixture(&db).await;
    let got = db
        .search_findings(
            &FindingFilter::new()
                .session(id)
                .target("https://b.example.com/users"),
        )
        .await
        .unwrap();
    assert_eq!(titles(&got), ["Endpoint discovered", "IDOR on users"]);
}

#[tokio::test]
async fn filter_by_free_text_is_case_insensitive() {
    let (_dir, _path, db) = open_temp().await;
    let id = seed_filter_fixture(&db).await;
    let got = db
        .search_findings(&FindingFilter::new().session(id).query("cors"))
        .await
        .unwrap();
    assert_eq!(
        titles(&got),
        ["CORS configured correctly", "Permissive CORS origin"]
    );
}

#[tokio::test]
async fn filter_by_date_range() {
    let (_dir, _path, db) = open_temp().await;
    let id = seed_filter_fixture(&db).await;
    let got = db
        .search_findings(
            &FindingFilter::new()
                .session(id)
                .date_range(ts(200), ts(400)),
        )
        .await
        .unwrap();
    assert_eq!(
        titles(&got),
        [
            "CORS configured correctly",
            "Endpoint discovered",
            "IDOR on users"
        ]
    );
}

#[tokio::test]
async fn filters_combine_with_and() {
    let (_dir, _path, db) = open_temp().await;
    let id = seed_filter_fixture(&db).await;
    let got = db
        .search_findings(
            &FindingFilter::new()
                .session(id)
                .status(Status::Vulnerable)
                .scanner_id("cors"),
        )
        .await
        .unwrap();
    assert_eq!(titles(&got), ["Permissive CORS origin"]);
}

#[tokio::test]
async fn search_orders_newest_first_and_honors_limit() {
    let (_dir, _path, db) = open_temp().await;
    let id = seed_filter_fixture(&db).await;

    // No filter beyond the session → all five, newest-first by timestamp.
    let all = db
        .search_findings(&FindingFilter::new().session(id))
        .await
        .unwrap();
    let order: Vec<&str> = all.iter().map(|f| f.finding.title.as_str()).collect();
    assert_eq!(
        order,
        [
            "Permissive CORS origin",    // ts 500
            "IDOR on users",             // ts 400
            "Endpoint discovered",       // ts 300
            "CORS configured correctly", // ts 200
            "SQL injection in login",    // ts 100
        ]
    );

    // A limit caps the result while keeping the newest.
    let limited = db
        .search_findings(&FindingFilter::new().session(id).limit(2))
        .await
        .unwrap();
    assert_eq!(limited.len(), 2);
    assert_eq!(limited[0].finding.title, "Permissive CORS origin");
    assert_eq!(limited[1].finding.title, "IDOR on users");
}

// --- 5.4 Summary counts -------------------------------------------------------

#[tokio::test]
async fn summary_counts_over_all_and_subset() {
    let (_dir, _path, db) = open_temp().await;
    let a = seed_filter_fixture(&db).await; // 5 findings under session A

    // A second session with two findings.
    let b = Uuid::new_v4();
    db.upsert_session(&session_record(b, SessionStatus::Completed))
        .await
        .unwrap();
    let target = Target::parse("https://c.example.com").unwrap();
    db.save_finding(
        b,
        &finding(
            "cors",
            target.clone(),
            Status::Vulnerable,
            Severity::High,
            "x",
            ts(10),
        ),
    )
    .await
    .unwrap();
    db.save_finding(
        b,
        &finding(
            "cors",
            target,
            Status::Vulnerable,
            Severity::High,
            "y",
            ts(20),
        ),
    )
    .await
    .unwrap();

    // Whole store.
    let all = db.summary_counts(None).await.unwrap();
    assert_eq!(all.sessions, 2);
    assert_eq!(all.findings, 7);
    assert_eq!(all.by_severity[&Severity::High], 3); // 1 in A + 2 in B
    assert_eq!(all.by_severity[&Severity::Critical], 1);
    assert_eq!(all.by_severity[&Severity::Low], 1);
    // Every severity level is present, even at zero.
    assert_eq!(all.by_severity.len(), 5);

    // Restricted to session A only.
    let only_a = db.summary_counts(Some(&[a])).await.unwrap();
    assert_eq!(only_a.sessions, 1);
    assert_eq!(only_a.findings, 5);
    assert_eq!(only_a.by_severity[&Severity::High], 1);

    // Empty subset → all zero.
    let none = db.summary_counts(Some(&[])).await.unwrap();
    assert_eq!(none.sessions, 0);
    assert_eq!(none.findings, 0);
    assert_eq!(none.by_severity, all_severities_zero());
}

fn all_severities_zero() -> BTreeMap<Severity, i64> {
    [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ]
    .into_iter()
    .map(|s| (s, 0))
    .collect()
}

// --- 7.4 Migration idempotency ------------------------------------------------

#[tokio::test]
async fn migrations_are_idempotent_and_preserve_data() {
    let (_dir, path) = temp_db_path();
    let id = Uuid::new_v4();

    // First open applies the migration; write some data, then close.
    {
        let db = DatabaseManager::open(&path).await.unwrap();
        db.upsert_session(&session_record(id, SessionStatus::Completed))
            .await
            .unwrap();
        let target = Target::parse("https://a.example.com").unwrap();
        db.save_finding(
            id,
            &finding(
                "cors",
                target,
                Status::Info,
                Severity::Info,
                "keep me",
                ts(1),
            ),
        )
        .await
        .unwrap();

        let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(applied, 1, "exactly one migration recorded");
        db.close().await;
    }

    // Reopen twice more: each re-run of migrations is a no-op (no error, no new
    // migration row) and the existing data is untouched.
    for _ in 0..2 {
        let db = DatabaseManager::open(&path).await.unwrap();
        let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(applied, 1, "no extra migration applied on reopen");

        // Schema is present and the data is intact.
        let stored = db.get_session(id).await.unwrap().unwrap();
        assert_eq!(stored.record.status, SessionStatus::Completed);
        assert_eq!(db.findings_for_session(id).await.unwrap().len(), 1);
        db.close().await;
    }
}

// --- 7.5 Deletion -------------------------------------------------------------

#[tokio::test]
async fn deleting_a_session_removes_it_and_its_findings_only() {
    let (_dir, _path, db) = open_temp().await;
    let keep = seed_filter_fixture(&db).await; // session A, 5 findings

    // A second session to prove it is unaffected.
    let drop_id = Uuid::new_v4();
    db.upsert_session(&session_record(drop_id, SessionStatus::Completed))
        .await
        .unwrap();
    let target = Target::parse("https://gone.example.com").unwrap();
    db.save_finding(
        drop_id,
        &finding(
            "cors",
            target,
            Status::Vulnerable,
            Severity::High,
            "doomed",
            ts(1),
        ),
    )
    .await
    .unwrap();

    // Delete reports it removed a session.
    assert!(db.delete_session(drop_id).await.unwrap());

    // The session and all of its findings are gone.
    assert!(db.get_session(drop_id).await.unwrap().is_none());
    assert!(db.findings_for_session(drop_id).await.unwrap().is_empty());

    // The other session is untouched.
    assert!(db.get_session(keep).await.unwrap().is_some());
    assert_eq!(db.findings_for_session(keep).await.unwrap().len(), 5);

    // Deleting again, or deleting an unknown id, reports nothing removed.
    assert!(!db.delete_session(drop_id).await.unwrap());
    assert!(!db.delete_session(Uuid::new_v4()).await.unwrap());
}
