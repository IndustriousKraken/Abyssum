//! Integration tests for the `result-persistence` capability.
//!
//! Every test runs against a temporary on-disk SQLite file in its own temp dir, so
//! reopening the pool genuinely exercises restart survival. No network, no real
//! targets — all data is synthetic.

use chrono::{DateTime, TimeZone, Utc};

use abyssum_core::{
    DatabaseManager, Finding, FindingFilter, ScanSession, SessionStatus, Severity, Status, Target,
};

/// A fixed UTC timestamp (zero nanoseconds, so it round-trips exactly).
fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 12, 0, 0).unwrap()
}

/// Open a fresh store at a temp path. Returns the manager and the owning tempdir
/// (kept alive for the test's duration — dropping it deletes the file).
async fn fresh_store() -> (DatabaseManager, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("abyssum.db");
    let db = DatabaseManager::connect(&path).await.unwrap();
    (db, dir)
}

fn target(url: &str) -> Target {
    Target::parse(url).unwrap()
}

/// A finding with every optional field populated, for round-trip coverage.
fn rich_finding(
    scanner: &str,
    target: Target,
    severity: Severity,
    status: Status,
    title: &str,
    timestamp: DateTime<Utc>,
) -> Finding {
    Finding::builder(scanner, target, title)
        .severity(severity)
        .status(status)
        .description(format!("{title} — full description"))
        .recommendations("Apply the documented remediation")
        .evidence(serde_json::json!({ "request": "GET /x", "status": 200, "n": 42 }))
        .timestamp(timestamp)
        .build()
}

// --- 7.1 Restart survival --------------------------------------------------

#[tokio::test]
async fn session_and_findings_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("abyssum.db");

    let targets = vec![
        target("https://api.example.com").with_path("/v1"),
        target("https://api2.example.com"),
    ];
    let scanner_ids = vec!["rest_discovery".to_string(), "cors".to_string()];

    let mut session = ScanSession::new(targets.clone(), scanner_ids.clone());
    session.status = SessionStatus::Completed;
    session.started_at = Some(ts(2026, 6, 20));
    session.finished_at = Some(ts(2026, 6, 21));
    session.error_count = 2;
    session.completed_units = 4;
    session.total_units = 4;
    let session_id = session.id;

    let f1 = rich_finding(
        "rest_discovery",
        target("https://api.example.com").with_path("/v1/users"),
        Severity::High,
        Status::Vulnerable,
        "Exposed admin endpoint",
        ts(2026, 6, 20),
    );
    let f2 = rich_finding(
        "cors",
        target("https://api2.example.com"),
        Severity::Low,
        Status::Info,
        "Reflective CORS observed",
        ts(2026, 6, 21),
    );

    {
        let db = DatabaseManager::connect(&path).await.unwrap();
        db.save_session(&session).await.unwrap();
        db.save_finding(session_id, &f1).await.unwrap();
        db.save_finding(session_id, &f2).await.unwrap();
        db.close().await;
    }

    // Reopen the same file — a genuine "process restarted" path.
    let db = DatabaseManager::connect(&path).await.unwrap();
    let loaded = db
        .get_session(session_id)
        .await
        .unwrap()
        .expect("session should survive the restart");

    assert_eq!(loaded.id, session_id);
    assert_eq!(loaded.status, SessionStatus::Completed);
    assert_eq!(loaded.targets, targets);
    assert_eq!(loaded.scanner_ids, scanner_ids);
    assert_eq!(loaded.error_count, 2);
    assert_eq!(loaded.completed_units, 4);
    assert_eq!(loaded.total_units, 4);
    assert_eq!(loaded.started_at, Some(ts(2026, 6, 20)));
    assert_eq!(loaded.finished_at, Some(ts(2026, 6, 21)));
    assert_eq!(loaded.findings.len(), 2);
}

// --- 7.2 Finding field integrity ------------------------------------------

#[tokio::test]
async fn finding_keeps_every_field_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("abyssum.db");

    let session = ScanSession::new(
        vec![target("https://shop.example.com")],
        vec!["idor".into()],
    );
    let finding_target = target("https://shop.example.com")
        .with_path("/orders")
        .with_id_template("/orders/{id}");
    let finding = rich_finding(
        "idor",
        finding_target.clone(),
        Severity::Critical,
        Status::Vulnerable,
        "IDOR on order references",
        ts(2026, 6, 22),
    );

    let assigned_id;
    {
        let db = DatabaseManager::connect(&path).await.unwrap();
        db.save_session(&session).await.unwrap();
        assigned_id = db.save_finding(session.id, &finding).await.unwrap();
        db.close().await;
    }

    let db = DatabaseManager::connect(&path).await.unwrap();
    let findings = db.get_findings(session.id).await.unwrap();
    assert_eq!(findings.len(), 1);
    let read = &findings[0];

    // Stable id is assigned and matches what save returned.
    assert_eq!(read.id, Some(assigned_id));
    assert_eq!(read.scanner_id, "idor");
    assert_eq!(read.target, finding_target); // base_url + path + id_template round-trip
    assert_eq!(read.status, Status::Vulnerable);
    assert_eq!(read.severity, Severity::Critical);
    assert_eq!(read.title, "IDOR on order references");
    assert_eq!(
        read.description.as_deref(),
        Some("IDOR on order references — full description")
    );
    assert_eq!(
        read.recommendations.as_deref(),
        Some("Apply the documented remediation")
    );
    assert_eq!(read.timestamp, ts(2026, 6, 22));
    // Evidence JSON round-trips without loss.
    let evidence = read.evidence.as_ref().expect("evidence present");
    assert_eq!(evidence["request"], "GET /x");
    assert_eq!(evidence["status"], 200);
    assert_eq!(evidence["n"], 42);
    assert_eq!(
        evidence,
        &serde_json::json!({ "request": "GET /x", "status": 200, "n": 42 })
    );
}

// --- 7.3 Filters -----------------------------------------------------------

/// Collect finding titles (sorted) so set-membership assertions ignore order.
fn titles(findings: &[Finding]) -> Vec<String> {
    let mut out: Vec<String> = findings.iter().map(|f| f.title.clone()).collect();
    out.sort();
    out
}

#[tokio::test]
async fn filters_return_exactly_the_seeded_matches() {
    let (db, _dir) = fresh_store().await;

    let t1 = target("https://a.example.com");
    let t2 = target("https://b.example.com");
    let t3 = target("https://c.example.com");

    let session = ScanSession::new(
        vec![t1.clone(), t2.clone(), t3.clone()],
        vec!["rest".into()],
    );
    db.save_session(&session).await.unwrap();
    let sid = session.id;

    // f_a: rest / High / Vulnerable / t1 / day 1
    db.save_finding(
        sid,
        &rich_finding(
            "rest",
            t1.clone(),
            Severity::High,
            Status::Vulnerable,
            "SQL injection in login",
            ts(2026, 1, 1),
        ),
    )
    .await
    .unwrap();
    // f_b: cors / Low / Safe / t2 / day 2
    db.save_finding(
        sid,
        &rich_finding(
            "cors",
            t2.clone(),
            Severity::Low,
            Status::Safe,
            "Permissive CORS header",
            ts(2026, 1, 2),
        ),
    )
    .await
    .unwrap();
    // f_c: rest / Medium / Info / t1 / day 3
    db.save_finding(
        sid,
        &rich_finding(
            "rest",
            t1.clone(),
            Severity::Medium,
            Status::Info,
            "Verbose error message",
            ts(2026, 1, 3),
        ),
    )
    .await
    .unwrap();
    // f_d: idor / Critical / Vulnerable / t3 / day 4
    db.save_finding(
        sid,
        &rich_finding(
            "idor",
            t3.clone(),
            Severity::Critical,
            Status::Vulnerable,
            "IDOR on orders",
            ts(2026, 1, 4),
        ),
    )
    .await
    .unwrap();

    // By status.
    let vulns = db
        .search_findings(&FindingFilter::new().by_status(Status::Vulnerable))
        .await
        .unwrap();
    assert_eq!(titles(&vulns), ["IDOR on orders", "SQL injection in login"]);

    // By severity.
    let lows = db
        .search_findings(&FindingFilter::new().by_severity(Severity::Low))
        .await
        .unwrap();
    assert_eq!(titles(&lows), ["Permissive CORS header"]);

    // By scanner id.
    let rest = db
        .search_findings(&FindingFilter::new().by_scanner("rest"))
        .await
        .unwrap();
    assert_eq!(
        titles(&rest),
        ["SQL injection in login", "Verbose error message"]
    );

    // By target (full URL).
    let on_t1 = db
        .search_findings(&FindingFilter::new().by_target(t1.full_url().to_string()))
        .await
        .unwrap();
    assert_eq!(
        titles(&on_t1),
        ["SQL injection in login", "Verbose error message"]
    );

    // Free-text over title/description (case-insensitive).
    let cors = db
        .search_findings(&FindingFilter::new().matching("cors"))
        .await
        .unwrap();
    assert_eq!(titles(&cors), ["Permissive CORS header"]);
    let injection = db
        .search_findings(&FindingFilter::new().matching("injection"))
        .await
        .unwrap();
    assert_eq!(titles(&injection), ["SQL injection in login"]);

    // Date range (inclusive) over the finding timestamp.
    let mid = db
        .search_findings(&FindingFilter::new().from(ts(2026, 1, 2)).to(ts(2026, 1, 3)))
        .await
        .unwrap();
    assert_eq!(
        titles(&mid),
        ["Permissive CORS header", "Verbose error message"]
    );

    // Combined filters narrow the result (rest AND vulnerable -> only f_a).
    let combined = db
        .search_findings(
            &FindingFilter::new()
                .by_scanner("rest")
                .by_status(Status::Vulnerable),
        )
        .await
        .unwrap();
    assert_eq!(titles(&combined), ["SQL injection in login"]);
}

#[tokio::test]
async fn search_orders_newest_first_and_applies_limit() {
    let (db, _dir) = fresh_store().await;
    let t = target("https://x.example.com");
    let session = ScanSession::new(vec![t.clone()], vec!["rest".into()]);
    db.save_session(&session).await.unwrap();

    db.save_finding(
        session.id,
        &rich_finding(
            "rest",
            t.clone(),
            Severity::Info,
            Status::Info,
            "oldest",
            ts(2026, 1, 1),
        ),
    )
    .await
    .unwrap();
    db.save_finding(
        session.id,
        &rich_finding(
            "rest",
            t.clone(),
            Severity::Info,
            Status::Info,
            "middle",
            ts(2026, 1, 2),
        ),
    )
    .await
    .unwrap();
    db.save_finding(
        session.id,
        &rich_finding(
            "rest",
            t.clone(),
            Severity::Info,
            Status::Info,
            "newest",
            ts(2026, 1, 3),
        ),
    )
    .await
    .unwrap();

    let ordered = db.search_findings(&FindingFilter::new()).await.unwrap();
    let order: Vec<&str> = ordered.iter().map(|f| f.title.as_str()).collect();
    assert_eq!(order, ["newest", "middle", "oldest"]);

    let limited = db
        .search_findings(&FindingFilter::new().limit(2))
        .await
        .unwrap();
    let limited_order: Vec<&str> = limited.iter().map(|f| f.title.as_str()).collect();
    assert_eq!(limited_order, ["newest", "middle"]);
}

// --- 7.4 Migration idempotency --------------------------------------------

#[tokio::test]
async fn migrations_are_idempotent_and_preserve_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("abyssum.db");

    // First open creates and migrates the schema; store a session.
    let session = ScanSession::new(vec![target("https://example.com")], vec!["rest".into()]);
    {
        let db = DatabaseManager::connect(&path).await.unwrap();
        db.save_session(&session).await.unwrap();
        db.close().await;
    }

    // Second open re-applies migrations against the already-current store: a
    // no-op that must neither error nor discard the stored session, and must
    // leave the schema present (storing/reading still works).
    let db = DatabaseManager::connect(&path).await.unwrap();
    assert!(
        db.get_session(session.id).await.unwrap().is_some(),
        "existing data must survive a second migration pass"
    );

    let again = ScanSession::new(vec![target("https://example.org")], vec!["cors".into()]);
    db.save_session(&again).await.unwrap();
    assert!(db.get_session(again.id).await.unwrap().is_some());

    // The migration tracking table exists and records exactly one applied version.
    let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(applied, 1);
}

// --- 7.5 Deletion ----------------------------------------------------------

#[tokio::test]
async fn deleting_a_session_removes_it_and_its_findings_only() {
    let (db, _dir) = fresh_store().await;
    let t = target("https://example.com");

    let session_a = ScanSession::new(vec![t.clone()], vec!["rest".into()]);
    let session_b = ScanSession::new(vec![t.clone()], vec!["cors".into()]);
    db.save_session(&session_a).await.unwrap();
    db.save_session(&session_b).await.unwrap();

    db.save_finding(
        session_a.id,
        &rich_finding(
            "rest",
            t.clone(),
            Severity::High,
            Status::Vulnerable,
            "a-finding-1",
            ts(2026, 1, 1),
        ),
    )
    .await
    .unwrap();
    db.save_finding(
        session_a.id,
        &rich_finding(
            "rest",
            t.clone(),
            Severity::Low,
            Status::Info,
            "a-finding-2",
            ts(2026, 1, 2),
        ),
    )
    .await
    .unwrap();
    db.save_finding(
        session_b.id,
        &rich_finding(
            "cors",
            t.clone(),
            Severity::Medium,
            Status::Info,
            "b-finding-1",
            ts(2026, 1, 3),
        ),
    )
    .await
    .unwrap();

    // Delete A: reports removal.
    assert!(db.delete_session(session_a.id).await.unwrap());

    // A and its findings are gone...
    assert!(db.get_session(session_a.id).await.unwrap().is_none());
    assert!(db.get_findings(session_a.id).await.unwrap().is_empty());

    // ...while B and its findings are untouched.
    let b = db
        .get_session(session_b.id)
        .await
        .unwrap()
        .expect("B intact");
    assert_eq!(b.findings.len(), 1);
    assert_eq!(b.findings[0].title, "b-finding-1");

    // Deleting an absent session reports no removal.
    let absent = ScanSession::new(vec![], vec![]).id;
    assert!(!db.delete_session(absent).await.unwrap());
}

// --- Session query / upsert ------------------------------------------------

#[tokio::test]
async fn get_session_returns_none_for_unknown_id() {
    let (db, _dir) = fresh_store().await;
    let unknown = ScanSession::new(vec![], vec![]).id;
    assert!(db.get_session(unknown).await.unwrap().is_none());
}

#[tokio::test]
async fn re_saving_a_session_updates_it_in_place() {
    let (db, _dir) = fresh_store().await;
    let mut session = ScanSession::new(vec![target("https://example.com")], vec!["rest".into()]);
    db.save_session(&session).await.unwrap();

    // Advance the session and re-save under the same id.
    session.status = SessionStatus::Completed;
    session.completed_units = 3;
    session.total_units = 3;
    session.error_count = 1;
    session.started_at = Some(ts(2026, 6, 20));
    session.finished_at = Some(ts(2026, 6, 21));
    db.save_session(&session).await.unwrap();

    // Exactly one session row, carrying the latest values.
    let all = db.list_sessions(100, 0).await.unwrap();
    assert_eq!(all.len(), 1);
    let loaded = db.get_session(session.id).await.unwrap().unwrap();
    assert_eq!(loaded.status, SessionStatus::Completed);
    assert_eq!(loaded.completed_units, 3);
    assert_eq!(loaded.error_count, 1);
    assert_eq!(loaded.finished_at, Some(ts(2026, 6, 21)));
}

#[tokio::test]
async fn list_sessions_is_newest_first_with_paging() {
    let (db, _dir) = fresh_store().await;
    let first = ScanSession::new(vec![target("https://1.example.com")], vec!["rest".into()]);
    let second = ScanSession::new(vec![target("https://2.example.com")], vec!["rest".into()]);
    let third = ScanSession::new(vec![target("https://3.example.com")], vec!["rest".into()]);
    db.save_session(&first).await.unwrap();
    db.save_session(&second).await.unwrap();
    db.save_session(&third).await.unwrap();

    // First page (newest two), then the remaining one.
    let page1 = db.list_sessions(2, 0).await.unwrap();
    assert_eq!(page1.len(), 2);
    assert_eq!(page1[0].id, third.id);
    assert_eq!(page1[1].id, second.id);

    let page2 = db.list_sessions(2, 2).await.unwrap();
    assert_eq!(page2.len(), 1);
    assert_eq!(page2[0].id, first.id);
}

// --- 5.4 Summary counts ----------------------------------------------------

#[tokio::test]
async fn summary_counts_sessions_findings_and_severity_breakdown() {
    let (db, _dir) = fresh_store().await;
    let t = target("https://example.com");

    let session_a = ScanSession::new(vec![t.clone()], vec!["rest".into()]);
    let session_b = ScanSession::new(vec![t.clone()], vec!["cors".into()]);
    db.save_session(&session_a).await.unwrap();
    db.save_session(&session_b).await.unwrap();

    db.save_finding(
        session_a.id,
        &rich_finding(
            "rest",
            t.clone(),
            Severity::High,
            Status::Vulnerable,
            "a1",
            ts(2026, 1, 1),
        ),
    )
    .await
    .unwrap();
    db.save_finding(
        session_a.id,
        &rich_finding(
            "rest",
            t.clone(),
            Severity::Low,
            Status::Info,
            "a2",
            ts(2026, 1, 2),
        ),
    )
    .await
    .unwrap();
    db.save_finding(
        session_b.id,
        &rich_finding(
            "cors",
            t.clone(),
            Severity::High,
            Status::Vulnerable,
            "b1",
            ts(2026, 1, 3),
        ),
    )
    .await
    .unwrap();
    db.save_finding(
        session_b.id,
        &rich_finding(
            "cors",
            t.clone(),
            Severity::Critical,
            Status::Vulnerable,
            "b2",
            ts(2026, 1, 4),
        ),
    )
    .await
    .unwrap();

    // Whole store.
    let all = db.summary(None).await.unwrap();
    assert_eq!(all.session_count, 2);
    assert_eq!(all.finding_count, 4);
    assert_eq!(all.by_severity[&Severity::High], 2);
    assert_eq!(all.by_severity[&Severity::Low], 1);
    assert_eq!(all.by_severity[&Severity::Critical], 1);
    assert_eq!(all.by_severity[&Severity::Medium], 0);
    assert_eq!(all.by_severity[&Severity::Info], 0);

    // Restricted to session A only.
    let scoped = db.summary(Some(&[session_a.id])).await.unwrap();
    assert_eq!(scoped.session_count, 1);
    assert_eq!(scoped.finding_count, 2);
    assert_eq!(scoped.by_severity[&Severity::High], 1);
    assert_eq!(scoped.by_severity[&Severity::Low], 1);
    assert_eq!(scoped.by_severity[&Severity::Critical], 0);

    // Restricted to an empty subset: nothing is counted.
    let none = db.summary(Some(&[])).await.unwrap();
    assert_eq!(none.session_count, 0);
    assert_eq!(none.finding_count, 0);
    assert!(none.by_severity.values().all(|&c| c == 0));
}

// --- 4.3 Round-trip of complex fields --------------------------------------

#[tokio::test]
async fn evidence_and_target_round_trip_without_loss() {
    let (db, _dir) = fresh_store().await;
    let complex_target = target("https://api.example.com:8443")
        .with_path("/v2/items")
        .with_id_template("/v2/items/{item_id}");
    let session = ScanSession::new(vec![complex_target.clone()], vec!["rest".into()]);
    db.save_session(&session).await.unwrap();

    let evidence = serde_json::json!({
        "headers": { "x-test": ["a", "b"], "nested": { "deep": true } },
        "list": [1, 2, 3],
        "unicode": "résumé ✓",
    });
    let finding = Finding::builder("rest", complex_target.clone(), "Complex evidence")
        .evidence(evidence.clone())
        .timestamp(ts(2026, 3, 3))
        .build();
    db.save_finding(session.id, &finding).await.unwrap();

    let read = &db.get_findings(session.id).await.unwrap()[0];
    assert_eq!(read.target, complex_target);
    assert_eq!(read.evidence.as_ref().unwrap(), &evidence);
}
