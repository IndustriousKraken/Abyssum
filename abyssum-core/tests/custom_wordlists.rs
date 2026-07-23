//! Integration tests for the `custom-wordlists` capability (g07).
//!
//! Each test runs against a temporary on-disk SQLite file with real registered
//! users. They exercise import + normalization reporting, per-user ownership (one
//! user never sees another's lists), and the scan-time named lookup that returns a
//! selected custom list or the seeded default.

use abyssum_core::{AuthConfig, AuthManager, CustomWordlistStore, DatabaseManager};

/// Open a fresh store plus the auth + custom-wordlist authorities over its pool.
async fn fresh() -> (
    AuthManager,
    CustomWordlistStore,
    DatabaseManager,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let db = DatabaseManager::connect(dir.path().join("abyssum.db"))
        .await
        .unwrap();
    let auth = AuthManager::new(db.pool().clone(), &AuthConfig::default());
    let wordlists = CustomWordlistStore::from_database(&db);
    (auth, wordlists, db, dir)
}

// --- Import stores a normalized list with a correct report ------------------

#[tokio::test]
async fn import_normalizes_and_reports() {
    let (auth, wordlists, db, _dir) = fresh().await;
    let alice = auth.register("alice", "pw").await.unwrap();

    // Blanks, a comment, surrounding whitespace, mixed case, and duplicates.
    let raw = "API\n  api  \n\n# a comment\nMail\nmail\nwww\n   \n";
    let (list, report) = wordlists.import(alice.id, "My Subs", raw).await.unwrap();

    // Three unique, normalized (lowercased) entries survived.
    assert_eq!(list.name, "My Subs");
    assert_eq!(list.owner_user_id, alice.id);
    assert_eq!(list.entry_count, 3);
    assert_eq!(report.imported, 3);
    assert_eq!(report.dropped_blank, 2);
    assert_eq!(report.dropped_comment, 1);
    assert_eq!(report.dropped_duplicate, 2);

    // The stored entries are exactly the normalized set, in import order.
    let values = db
        .reference_store()
        .custom_wordlist_values(list.id)
        .await
        .unwrap();
    assert_eq!(values, vec!["api", "mail", "www"]);

    // A second import under the same name is rejected (unique per owner).
    assert!(wordlists.import(alice.id, "My Subs", "x").await.is_err());
    // An import that normalizes to nothing is rejected rather than stored empty.
    assert!(
        wordlists
            .import(alice.id, "Empty", "\n# only\n")
            .await
            .is_err()
    );
}

// --- One user cannot see another's lists ------------------------------------

#[tokio::test]
async fn one_user_cannot_see_anothers_wordlists() {
    let (auth, wordlists, _db, _dir) = fresh().await;
    let alice = auth.register("alice", "pw").await.unwrap();
    let bob = auth.register("bob", "pw").await.unwrap();

    let alice_list = wordlists
        .import(alice.id, "Alice Only", "secret\ninternal")
        .await
        .unwrap()
        .0;

    // Bob's list never contains alice's list.
    let bob_lists = wordlists.list_for_user(bob.id).await.unwrap();
    assert!(bob_lists.is_empty(), "bob has no lists of his own yet");

    // Alice sees exactly her own.
    let alice_lists = wordlists.list_for_user(alice.id).await.unwrap();
    assert_eq!(alice_lists.len(), 1);
    assert!(alice_lists.iter().all(|w| w.owner_user_id == alice.id));

    // Bob cannot resolve alice's list by id (owner-scoped get ⇒ None).
    assert!(
        wordlists
            .get_for_user(bob.id, alice_list.id)
            .await
            .unwrap()
            .is_none(),
        "bob resolved a list he does not own"
    );
    // Alice can.
    assert!(
        wordlists
            .get_for_user(alice.id, alice_list.id)
            .await
            .unwrap()
            .is_some()
    );
}

// --- The selected list is used; the seeded default applies otherwise --------

#[tokio::test]
async fn named_lookup_returns_selected_custom_list_or_seeded_default() {
    let (auth, wordlists, db, _dir) = fresh().await;
    let alice = auth.register("alice", "pw").await.unwrap();
    let store = db.reference_store();

    // The seeded `subdomains` list is present by default (non-empty).
    let seeded = store.wordlist_values_for("subdomains", None).await.unwrap();
    assert!(
        !seeded.is_empty(),
        "the seeded subdomains list should exist"
    );

    // A custom list Alice imported is returned when selected for the scan.
    let list = wordlists
        .import(alice.id, "Recon", "onlythis\nsecond")
        .await
        .unwrap()
        .0;
    let selected = store
        .wordlist_values_for("subdomains", Some(list.id))
        .await
        .unwrap();
    assert_eq!(selected, vec!["onlythis", "second"]);
    assert_ne!(selected, seeded, "selection must override the default");

    // No selection ⇒ still the seeded default.
    let default_again = store.wordlist_values_for("subdomains", None).await.unwrap();
    assert_eq!(default_again, seeded);

    // Re-seeding the built-ins never disturbs the user's imported list.
    db.seed_reference_data().await.unwrap();
    let after_reseed = store
        .wordlist_values_for("subdomains", Some(list.id))
        .await
        .unwrap();
    assert_eq!(after_reseed, vec!["onlythis", "second"]);
}
