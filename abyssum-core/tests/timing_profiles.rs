//! Integration tests for the `timing-profiles` capability (g05).
//!
//! Each test runs against a temporary on-disk SQLite file, with real registered
//! users, exercising per-user ownership: the built-in library is seeded per user,
//! profiles are reusable, and one user can never see or edit another's.

use abyssum_core::{
    AuthConfig, AuthManager, DatabaseManager, PacingPolicy, TimingProfileStore, builtin_library,
};

/// Open a fresh store plus the auth + timing-profile authorities over its pool.
async fn fresh() -> (AuthManager, TimingProfileStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = DatabaseManager::connect(dir.path().join("abyssum.db"))
        .await
        .unwrap();
    let auth = AuthManager::new(db.pool().clone(), &AuthConfig::default());
    let timing = TimingProfileStore::from_database(&db);
    (auth, timing, dir)
}

// --- The built-in library is seeded per user -------------------------------

#[tokio::test]
async fn builtin_library_is_seeded_per_user() {
    let (auth, timing, _dir) = fresh().await;
    let alice = auth.register("alice", "pw").await.unwrap();

    let profiles = timing.list_for_user(alice.id).await.unwrap();
    // Every library entry is present, each owned by alice and flagged built-in.
    assert_eq!(profiles.len(), builtin_library().len());
    assert!(profiles.iter().all(|p| p.owner_user_id == alice.id));
    assert!(profiles.iter().all(|p| p.built_in));
    // An organic profile is in the seeded set.
    assert!(
        profiles
            .iter()
            .any(|p| matches!(p.policy, PacingPolicy::Organic { .. })),
        "the organic profile must be seeded"
    );

    // Re-seeding is a no-op: the count does not grow.
    let again = timing.list_for_user(alice.id).await.unwrap();
    assert_eq!(again.len(), profiles.len());
}

// --- A profile is reusable across scans (selectable repeatedly) -------------

#[tokio::test]
async fn a_profile_is_reusable_and_owner_scoped_get() {
    let (auth, timing, _dir) = fresh().await;
    let alice = auth.register("alice", "pw").await.unwrap();

    let created = timing
        .create(alice.id, "My Slow Crawl", &PacingPolicy::uniform(5.0, 12.0))
        .await
        .unwrap();

    // The same profile resolves for alice as many times as she starts a scan.
    for _ in 0..3 {
        let got = timing.get_for_user(alice.id, created.id).await.unwrap();
        assert_eq!(got.as_ref().map(|p| p.id), Some(created.id));
        assert_eq!(got.unwrap().policy, PacingPolicy::uniform(5.0, 12.0));
    }
}

// --- Create / adjust round-trip + duplicate-name rejection ------------------

#[tokio::test]
async fn create_and_update_round_trip() {
    let (auth, timing, _dir) = fresh().await;
    let alice = auth.register("alice", "pw").await.unwrap();

    let created = timing
        .create(alice.id, "Custom", &PacingPolicy::uniform(1.0, 2.0))
        .await
        .unwrap();
    assert!(!created.built_in);

    // A duplicate name is rejected.
    assert!(
        timing
            .create(alice.id, "Custom", &PacingPolicy::uniform(1.0, 2.0))
            .await
            .is_err()
    );

    // Adjusting changes the name and policy in place.
    let updated = timing
        .update(
            alice.id,
            created.id,
            "Custom (organic)",
            &PacingPolicy::organic(1.0, 6.0),
        )
        .await
        .unwrap();
    assert_eq!(updated.name, "Custom (organic)");
    assert!(matches!(updated.policy, PacingPolicy::Organic { .. }));

    let reloaded = timing
        .get_for_user(alice.id, created.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.name, "Custom (organic)");
    assert!(matches!(reloaded.policy, PacingPolicy::Organic { .. }));
}

// --- Profiles are private to their owner ------------------------------------

#[tokio::test]
async fn one_user_cannot_see_or_edit_anothers_profiles() {
    let (auth, timing, _dir) = fresh().await;
    let alice = auth.register("alice", "pw").await.unwrap();
    let bob = auth.register("bob", "pw").await.unwrap();

    let alice_profile = timing
        .create(alice.id, "Alice Only", &PacingPolicy::uniform(2.0, 4.0))
        .await
        .unwrap();

    // Bob's list (his own seeded built-ins) never contains alice's profile.
    let bob_profiles = timing.list_for_user(bob.id).await.unwrap();
    assert!(
        bob_profiles.iter().all(|p| p.owner_user_id == bob.id),
        "bob must only see his own profiles"
    );
    assert!(
        !bob_profiles.iter().any(|p| p.name == "Alice Only"),
        "alice's private profile leaked into bob's list"
    );

    // Bob cannot resolve alice's profile by its id (owner-scoped get ⇒ None).
    assert!(
        timing
            .get_for_user(bob.id, alice_profile.id)
            .await
            .unwrap()
            .is_none(),
        "bob resolved a profile he does not own"
    );

    // Bob cannot adjust alice's profile.
    assert!(
        timing
            .update(
                bob.id,
                alice_profile.id,
                "Hijacked",
                &PacingPolicy::uniform(0.0, 0.1),
            )
            .await
            .is_err(),
        "bob edited a profile he does not own"
    );

    // Alice's profile is intact — bob's failed edit changed nothing.
    let intact = timing
        .get_for_user(alice.id, alice_profile.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(intact.name, "Alice Only");
    assert_eq!(intact.policy, PacingPolicy::uniform(2.0, 4.0));
}
