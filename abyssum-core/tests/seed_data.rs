//! Integration tests for the `seed-data` capability (tasks 6.1–6.3).
//!
//! Every test runs against a temporary on-disk SQLite file in its own temp dir,
//! seeded from the bundled assets — no network, no real targets. Opening the
//! store self-seeds it (see [`DatabaseManager::connect`]); the idempotency test
//! then re-seeds explicitly.

use std::collections::BTreeSet;

use abyssum_core::seed;
use abyssum_core::{
    DatabaseManager, RotatingUserAgent, SingleUserAgent, UserAgentRotation, UserAgentSource,
};

/// Open a fresh, self-seeded store at a temp path. Returns the manager and the
/// owning tempdir (kept alive for the test — dropping it deletes the file).
async fn fresh_store() -> (DatabaseManager, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("abyssum.db");
    let db = DatabaseManager::connect(&path).await.unwrap();
    (db, dir)
}

/// The distinct values bundled for a named list, computed from the embedded asset
/// with the same parsing the seeder uses.
fn expected_values(list_name: &str) -> BTreeSet<String> {
    let asset = seed::WORDLISTS
        .iter()
        .find(|a| a.name == list_name)
        .expect("list is bundled");
    seed::parse_wordlist(asset)
        .into_iter()
        .map(|entry| entry.value)
        .collect()
}

// --- 6.1 Idempotent re-seed ------------------------------------------------

#[tokio::test]
async fn re_seeding_does_not_duplicate_rows() {
    let (db, _dir) = fresh_store().await;
    let store = db.reference_store();

    // Counts after the connect-time seed.
    let mut before = Vec::new();
    for asset in seed::WORDLISTS {
        before.push(store.wordlist(asset.name).await.unwrap().len());
    }
    let ua_before = store.user_agents().await.unwrap().len();

    // Seed twice more — must top up nothing and never error.
    db.seed_reference_data().await.unwrap();
    db.seed_reference_data().await.unwrap();

    for (asset, expected) in seed::WORDLISTS.iter().zip(before) {
        let got = store.wordlist(asset.name).await.unwrap().len();
        assert_eq!(got, expected, "{} row count changed on re-seed", asset.name);
        // No duplicate (list_name, value) pairs survived.
        assert_eq!(got, expected_values(asset.name).len());
    }
    assert_eq!(store.user_agents().await.unwrap().len(), ua_before);
}

// --- 6.2 Named lists load, match counts, labels preserved ------------------

#[tokio::test]
async fn every_named_list_loads_and_matches_the_bundled_count() {
    let (db, _dir) = fresh_store().await;
    let store = db.reference_store();

    for asset in seed::WORDLISTS {
        let entries = store.wordlist(asset.name).await.unwrap();
        let expected = expected_values(asset.name);
        assert!(!entries.is_empty(), "{} loaded empty", asset.name);
        assert_eq!(
            entries.len(),
            expected.len(),
            "{} count != bundled asset count",
            asset.name
        );
        let loaded: BTreeSet<String> = entries.iter().map(|e| e.value.clone()).collect();
        assert_eq!(loaded, expected, "{} values differ from bundle", asset.name);
    }
}

#[tokio::test]
async fn a_scanner_can_load_more_than_one_named_list_independently() {
    let (db, _dir) = fresh_store().await;
    let store = db.reference_store();

    // graphql draws on both its paths and its named queries.
    let paths = store.wordlist("graphql_paths").await.unwrap();
    let queries = store.wordlist("graphql_queries").await.unwrap();
    assert!(!paths.is_empty());
    assert!(!queries.is_empty());
    // The two lists are distinct sets.
    assert_ne!(paths[0].value, queries[0].value);
}

#[tokio::test]
async fn labeled_graphql_entries_carry_both_label_and_body() {
    let (db, _dir) = fresh_store().await;
    let store = db.reference_store();

    let entries = store.wordlist("graphql_queries").await.unwrap();
    for entry in &entries {
        assert!(entry.label.is_some(), "graphql query missing its label");
        assert!(!entry.value.is_empty(), "graphql query missing its body");
    }
    // A known query keeps both halves through the split-and-seed round trip.
    assert!(
        entries
            .iter()
            .any(|e| e.label.as_deref() == Some("Introspection Query")
                && e.value.contains("__schema"))
    );
    // Plain lists, by contrast, carry no labels.
    let plain = store.wordlist("rest_endpoints").await.unwrap();
    assert!(plain.iter().all(|e| e.label.is_none()));
}

#[tokio::test]
async fn ordering_is_preserved_from_the_bundled_asset() {
    let (db, _dir) = fresh_store().await;
    let store = db.reference_store();

    // The first few seeded values match the asset's order (position column).
    let asset = seed::WORDLISTS
        .iter()
        .find(|a| a.name == "bac_paths")
        .unwrap();
    let parsed = seed::parse_wordlist(asset);
    let loaded = store.wordlist("bac_paths").await.unwrap();
    for (a, b) in parsed.iter().zip(loaded.iter()) {
        assert_eq!(a.value, b.value, "seeded order diverged from the asset");
    }
}

// --- 4.3 Missing list is graceful ------------------------------------------

#[tokio::test]
async fn missing_list_returns_empty_not_an_error() {
    let (db, _dir) = fresh_store().await;
    let store = db.reference_store();

    let entries = store.wordlist("no_such_list").await.unwrap();
    assert!(entries.is_empty());
    let values = store.wordlist_values("no_such_list").await.unwrap();
    assert!(values.is_empty());
}

// --- UA pool is present, marked realistic-or-not ---------------------------

#[tokio::test]
async fn user_agent_pool_is_present_and_classified() {
    let (db, _dir) = fresh_store().await;
    let pool = db.reference_store().user_agents().await.unwrap();
    assert!(!pool.is_empty());
    assert!(pool.iter().any(|u| u.realistic), "no realistic identities");
    assert!(pool.iter().any(|u| !u.realistic), "no opt-in identities");
}

// --- 6.3 Default UA rotation: realistic only, varied; opt-in reaches others -

#[tokio::test]
async fn default_rotation_returns_only_realistic_identities_and_varies() {
    let (db, _dir) = fresh_store().await;
    let store = db.reference_store();

    let realistic: BTreeSet<String> = store
        .realistic_user_agents()
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert!(
        realistic.len() > 1,
        "need >1 realistic UA to demonstrate variation"
    );

    let source = RotatingUserAgent::from_store(&store, UserAgentRotation::PerRequest)
        .await
        .unwrap();

    let mut seen = BTreeSet::new();
    for _ in 0..200 {
        let ua = source.next_user_agent();
        assert!(
            realistic.contains(&ua),
            "default rotation used a non-realistic UA: {ua}"
        );
        assert!(
            !ua.contains("Abyssum"),
            "default rotation announced the scanner"
        );
        seen.insert(ua);
    }
    assert!(
        seen.len() > 1,
        "default rotation never varied across many requests"
    );
}

#[tokio::test]
async fn explicit_opt_in_can_reach_non_realistic_identities() {
    let (db, _dir) = fresh_store().await;
    let pool = db.reference_store().user_agents().await.unwrap();

    // An operator can deliberately select a scanner-announcing identity from the
    // pool; the default rotation would never surface it.
    let non_realistic = pool
        .iter()
        .find(|u| !u.realistic)
        .expect("pool has an opt-in-only identity");
    let source = SingleUserAgent::new(non_realistic.value.clone());
    assert_eq!(source.next_user_agent(), non_realistic.value);
}

#[tokio::test]
async fn per_scan_rotation_pins_a_single_realistic_identity() {
    let (db, _dir) = fresh_store().await;
    let store = db.reference_store();
    let realistic: BTreeSet<String> = store
        .realistic_user_agents()
        .await
        .unwrap()
        .into_iter()
        .collect();

    let source = RotatingUserAgent::from_store(&store, UserAgentRotation::PerScan)
        .await
        .unwrap();
    let pinned = source.next_user_agent();
    assert!(realistic.contains(&pinned));
    for _ in 0..50 {
        assert_eq!(source.next_user_agent(), pinned);
    }
}
