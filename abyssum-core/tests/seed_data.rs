//! Seed-data integration tests — local only, no network to real targets.
//!
//! Every test runs against a temporary on-disk SQLite file. They cover the task
//! list directly: idempotent re-seeding without duplicates (6.1), named-list
//! retrieval matching the bundled counts with labelled GraphQL entries and
//! graceful handling of an absent list (6.2), and the default rotating User-Agent
//! drawing only from the realistic pool while explicit opt-in reaches the others
//! (6.3). Two extra tests drive a loopback HTTP listener to prove the rotating
//! identity actually reaches the wire through `ScanContext::send` and that the
//! `scanning.user_agent_rotation` config key changes that behaviour.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use abyssum_core::scan::BaseScanner;
use abyssum_core::{
    bundled_user_agents, bundled_wordlist, Config, DatabaseManager, Finding, Orchestrator,
    RateLimiter, RequestSpec, RotatingUserAgent, ScanContext, ScannerRegistry, SeedStore,
    SingleUserAgent, Target, UserAgentRotation, UserAgentSource,
};
use async_trait::async_trait;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Open a `DatabaseManager` on a fresh temp file; keep the `TempDir` alive so the
/// file survives for the test.
async fn open_temp() -> (TempDir, DatabaseManager) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("seed.db");
    let db = DatabaseManager::open(&path).await.unwrap();
    (dir, db)
}

/// A seeded store over a fresh temp database.
async fn seeded_store() -> (TempDir, DatabaseManager, SeedStore) {
    let (dir, db) = open_temp().await;
    let store = SeedStore::from_manager(&db);
    store.seed().await.unwrap();
    (dir, db, store)
}

/// Total rows in a table.
async fn count(db: &DatabaseManager, table: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    sqlx::query_scalar::<_, i64>(&sql)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

// --- 6.1 Idempotent seeding --------------------------------------------------

#[tokio::test]
async fn seeding_twice_creates_no_duplicates() {
    let (_dir, db, store) = seeded_store().await;

    let lists_after_first = count(&db, "wordlists").await;
    let entries_after_first = count(&db, "wordlist_entries").await;
    let uas_after_first = count(&db, "user_agents").await;
    assert!(lists_after_first > 0 && entries_after_first > 0 && uas_after_first > 0);

    // Seed again: a no-op against a fully populated store.
    let summary = store.seed().await.unwrap();
    assert!(
        summary.is_noop(),
        "re-seed must insert nothing: {summary:?}"
    );

    assert_eq!(count(&db, "wordlists").await, lists_after_first);
    assert_eq!(count(&db, "wordlist_entries").await, entries_after_first);
    assert_eq!(count(&db, "user_agents").await, uas_after_first);

    // No (list_name, value) pair appears twice, and no UA value appears twice.
    let dup_entries: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM (SELECT list_name, value FROM wordlist_entries \
         GROUP BY list_name, value HAVING COUNT(*) > 1)",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(dup_entries, 0, "duplicate wordlist entries");

    let dup_uas: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM (SELECT value FROM user_agents GROUP BY value HAVING COUNT(*) > 1)",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(dup_uas, 0, "duplicate user agents");
}

#[tokio::test]
async fn partial_store_is_topped_up_without_duplicating() {
    let (_dir, db, store) = seeded_store().await;
    let entries_full = count(&db, "wordlist_entries").await;
    let uas_full = count(&db, "user_agents").await;

    // Simulate a partially-populated store by deleting some rows.
    sqlx::query("DELETE FROM wordlist_entries WHERE list_name = 'subdomains'")
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM user_agents WHERE realistic = 0")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(count(&db, "wordlist_entries").await < entries_full);
    assert!(count(&db, "user_agents").await < uas_full);

    // Re-seeding restores exactly the missing rows and nothing more.
    let summary = store.seed().await.unwrap();
    assert!(!summary.is_noop());
    assert_eq!(count(&db, "wordlist_entries").await, entries_full);
    assert_eq!(count(&db, "user_agents").await, uas_full);
}

// --- 6.2 Named-list retrieval ------------------------------------------------

#[tokio::test]
async fn every_named_list_loads_and_matches_the_bundled_count() {
    let (_dir, _db, store) = seeded_store().await;

    for name in [
        "rest_endpoints",
        "rest_api_bases",
        "openapi_paths",
        "bac_paths",
        "bac_paths_short",
        "graphql_paths",
        "graphql_queries",
        "subdomains",
    ] {
        let bundled = bundled_wordlist(name);
        let loaded = store.wordlist(name).await.unwrap();
        assert!(!loaded.is_empty(), "{name} loaded empty");
        assert_eq!(
            loaded.len(),
            bundled.len(),
            "{name} row count must match the bundled asset count"
        );
        // Seeded order is preserved.
        assert_eq!(
            loaded, bundled,
            "{name} entries must load in bundled order with matching labels"
        );
    }
}

#[tokio::test]
async fn graphql_queries_carry_both_label_and_body() {
    let (_dir, _db, store) = seeded_store().await;
    let entries = store.wordlist("graphql_queries").await.unwrap();
    assert!(!entries.is_empty());
    for entry in &entries {
        let label = entry.label.as_deref().unwrap_or_default();
        assert!(
            !label.is_empty(),
            "every GraphQL entry needs a label: {entry:?}"
        );
        assert!(!entry.value.is_empty(), "every GraphQL entry needs a body");
    }
    // Plain lists carry no label, by contrast.
    let plain = store.wordlist("subdomains").await.unwrap();
    assert!(plain.iter().all(|e| e.label.is_none()));
}

#[tokio::test]
async fn absent_list_returns_no_candidates_not_an_error() {
    let (_dir, _db, store) = seeded_store().await;
    let missing = store.wordlist("no_such_list").await.unwrap();
    assert!(missing.is_empty(), "an absent list yields no candidates");
    let values = store.wordlist_values("no_such_list").await.unwrap();
    assert!(values.is_empty());
}

// --- 6.3 Realistic rotating User-Agent ---------------------------------------

#[tokio::test]
async fn user_agent_pool_marks_each_entry_realistic_or_not() {
    let (_dir, _db, store) = seeded_store().await;
    let pool = store.user_agents().await.unwrap();
    assert_eq!(pool.len(), bundled_user_agents().unwrap().len());
    assert!(pool.iter().any(|ua| ua.realistic));
    assert!(pool.iter().any(|ua| !ua.realistic));
}

#[tokio::test]
async fn default_rotation_only_returns_realistic_and_varies() {
    let (_dir, _db, store) = seeded_store().await;
    let realistic: HashSet<String> = store
        .realistic_user_agents()
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert!(
        realistic.len() > 1,
        "need a multi-entry pool to show variation"
    );

    let source = RotatingUserAgent::from_store(&store).await.unwrap();
    let mut seen = HashSet::new();
    for _ in 0..300 {
        let ua = source.next_user_agent();
        assert!(
            realistic.contains(&ua),
            "default rotation must never present a non-realistic identity: {ua:?}"
        );
        seen.insert(ua);
    }
    assert!(
        seen.len() > 1,
        "the default rotation must vary across requests"
    );
}

#[tokio::test]
async fn explicit_opt_in_can_reach_a_non_realistic_identity() {
    let (_dir, _db, store) = seeded_store().await;
    // Find a scanner-announcing identity from the pool (never used by default).
    let non_realistic = store
        .user_agents()
        .await
        .unwrap()
        .into_iter()
        .find(|ua| !ua.realistic)
        .expect("the pool contains non-realistic identities");

    // The default rotation excludes it...
    let realistic = store.realistic_user_agents().await.unwrap();
    assert!(!realistic.contains(&non_realistic.value));

    // ...but an explicit single-identity source presents exactly it.
    let opt_in = SingleUserAgent::new(non_realistic.value.clone());
    assert_eq!(opt_in.next_user_agent(), non_realistic.value);
}

// --- 5.1 / 5.2 The rotation reaches the wire ---------------------------------

/// Accept exactly `expected` loopback connections, capture each request's
/// `User-Agent`, reply with a minimal `200`, and return the captured agents.
async fn capture_user_agents(listener: TcpListener, expected: usize) -> Vec<String> {
    let mut agents = Vec::with_capacity(expected);
    for _ in 0..expected {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = sock.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&buf);
        let ua = text
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("user-agent")
                    .then(|| value.trim().to_string())
            })
            .unwrap_or_default();
        agents.push(ua);
        let _ = sock
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .await;
    }
    agents
}

/// A config with no pacing delay, so wire tests run fast.
fn unpaced_config(rotation: UserAgentRotation) -> Config {
    let mut config = Config::default();
    config.scanning.min_delay = 0.0;
    config.scanning.max_delay = 0.0;
    config.scanning.user_agent_rotation = rotation;
    config
}

#[tokio::test]
async fn send_stamps_a_rotating_realistic_user_agent_on_the_wire() {
    let (_dir, _db, store) = seeded_store().await;
    let realistic: HashSet<String> = store
        .realistic_user_agents()
        .await
        .unwrap()
        .into_iter()
        .collect();
    let source = RotatingUserAgent::from_store(&store).await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = 40;
    let server = tokio::spawn(capture_user_agents(listener, requests));

    let ctx = ScanContext::new(
        Arc::new(Config::default()),
        RateLimiter::new(Duration::ZERO, Duration::ZERO),
        Arc::new(source),
        CancellationToken::new(),
    );
    let url = Url::parse(&format!("http://{addr}/probe")).unwrap();
    for _ in 0..requests {
        // The response body is irrelevant; we only care what UA went out.
        let _ = ctx.send(RequestSpec::get(url.clone())).await;
    }

    let captured = server.await.unwrap();
    assert_eq!(captured.len(), requests);
    for ua in &captured {
        assert!(
            realistic.contains(ua),
            "every wire User-Agent must be a realistic seeded entry: {ua:?}"
        );
    }
    let distinct: HashSet<&String> = captured.iter().collect();
    assert!(
        distinct.len() > 1,
        "the wire User-Agent must vary across requests"
    );
}

/// A stub scanner that issues exactly one request per target through the context,
/// so the engine-applied User-Agent is what lands on the wire.
#[derive(Clone)]
struct ProbingScanner {
    url: Url,
}

#[async_trait]
impl BaseScanner for ProbingScanner {
    fn id(&self) -> &str {
        "probe"
    }
    fn name(&self) -> &str {
        "Probing stub"
    }
    fn description(&self) -> &str {
        "Issues one request per target so the wire User-Agent can be observed"
    }
    async fn scan(
        &self,
        _target: &Target,
        ctx: &ScanContext,
    ) -> abyssum_core::Result<Vec<Finding>> {
        let _ = ctx.send(RequestSpec::get(self.url.clone())).await;
        Ok(Vec::new())
    }
}

/// Drive the orchestrator over `targets` targets with the given rotation config,
/// returning the User-Agents observed on the wire.
async fn user_agents_over_session(rotation: UserAgentRotation, targets: usize) -> Vec<String> {
    let (_dir, _db, store) = seeded_store().await;
    let source = RotatingUserAgent::from_store(&store).await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(capture_user_agents(listener, targets));

    let url = Url::parse(&format!("http://{addr}/probe")).unwrap();
    let config = Arc::new(unpaced_config(rotation));
    let mut registry = ScannerRegistry::new(config.clone());
    let scanner = ProbingScanner { url };
    registry.register(
        "probe".to_string(),
        Arc::new(move |_cfg| Box::new(scanner.clone()) as Box<dyn BaseScanner>),
    );
    let orch = Orchestrator::new(config, registry).with_user_agent_source(Arc::new(source));

    // Distinct paths keep the targets distinct units while all hit the listener.
    let target_list: Vec<Target> = (0..targets)
        .map(|i| {
            Target::parse(&format!("http://{addr}"))
                .unwrap()
                .with_path(format!("/probe/{i}"))
        })
        .collect();

    orch.run_session(target_list, vec!["probe".to_string()], None)
        .await
        .unwrap();

    server.await.unwrap()
}

#[tokio::test]
async fn per_scan_rotation_pins_one_identity_for_the_whole_session() {
    let captured = user_agents_over_session(UserAgentRotation::PerScan, 16).await;
    assert_eq!(captured.len(), 16);
    let distinct: HashSet<&String> = captured.iter().collect();
    assert_eq!(
        distinct.len(),
        1,
        "per-scan rotation must hold one identity for the session: {distinct:?}"
    );
}

#[tokio::test]
async fn per_request_rotation_varies_within_one_session() {
    // 30 requests over a 7-entry realistic pool: all-identical is statistically
    // impossible, so a single distinct value would be a real regression.
    let captured = user_agents_over_session(UserAgentRotation::PerRequest, 30).await;
    assert_eq!(captured.len(), 30);
    let distinct: HashSet<&String> = captured.iter().collect();
    assert!(
        distinct.len() > 1,
        "per-request rotation must vary the identity within a session: {distinct:?}"
    );
}
