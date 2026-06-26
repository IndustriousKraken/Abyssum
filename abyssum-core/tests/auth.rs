//! Integration tests for the `authentication` capability (c02).
//!
//! Every test runs against a temporary on-disk SQLite file in its own temp dir
//! (the same store the persistence tests use). No network, no real targets — all
//! data is synthetic. Session expiry is forced deterministically by configuring a
//! zero-length lifetime rather than sleeping.

use abyssum_core::{
    visible_session, visible_sessions, AuthConfig, AuthManager, DatabaseManager, Error, Role,
    ScanSession, SessionStatus, Target,
};

/// Open a fresh store plus an [`AuthManager`] over its pool with default
/// lifetimes. Returns the manager, the auth authority, and the owning tempdir
/// (kept alive for the test — dropping it deletes the file).
async fn fresh() -> (DatabaseManager, AuthManager, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db = DatabaseManager::connect(dir.path().join("abyssum.db"))
        .await
        .unwrap();
    let auth = AuthManager::new(db.pool().clone(), &AuthConfig::default());
    (db, auth, dir)
}

/// An [`AuthConfig`] with explicit lifetimes (hours, minutes).
fn lifetimes(absolute_max_hours: u64, idle_timeout_minutes: u64) -> AuthConfig {
    AuthConfig {
        session_absolute_max_hours: absolute_max_hours,
        session_idle_timeout_minutes: idle_timeout_minutes,
    }
}

fn target(url: &str) -> Target {
    Target::parse(url).unwrap()
}

// --- 5.1 Passwords are stored as hashes, and verify accepts the right one ---

#[tokio::test]
async fn stored_password_is_a_hash_and_correct_password_verifies() {
    let (db, auth, _dir) = fresh().await;
    auth.register("alice", "correct horse battery staple")
        .await
        .unwrap();

    // The stored credential is an Argon2id PHC string, not the plaintext.
    let stored: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE username = ?")
        .bind("alice")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_ne!(stored, "correct horse battery staple");
    assert!(
        stored.starts_with("$argon2id$"),
        "expected an Argon2id PHC string, got {stored:?}"
    );

    // The correct password authenticates (yields a token).
    let token = auth
        .login("alice", "correct horse battery staple")
        .await
        .unwrap();
    assert!(!token.is_empty());
}

// --- 5.2 Same password -> different stored hashes (random salt) -------------

#[tokio::test]
async fn same_password_registered_twice_yields_different_stored_hashes() {
    let (db, auth, _dir) = fresh().await;
    auth.register("alice", "shared-secret").await.unwrap();
    auth.register("bob", "shared-secret").await.unwrap();

    let hashes: Vec<String> = sqlx::query_scalar(
        "SELECT password_hash FROM users WHERE username IN ('alice', 'bob') ORDER BY username",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(hashes.len(), 2);
    assert_ne!(
        hashes[0], hashes[1],
        "a fresh random salt must make the two stored hashes differ"
    );
}

// --- 5.3 First-user-is-admin, others regular, duplicate rejected -----------

#[tokio::test]
async fn first_user_is_admin_others_regular_duplicate_rejected() {
    let (_db, auth, _dir) = fresh().await;

    let first = auth.register("root", "pw-1").await.unwrap();
    assert_eq!(
        first.role,
        Role::Admin,
        "the first registrant must be admin"
    );
    assert!(first.is_admin());

    let second = auth.register("intern", "pw-2").await.unwrap();
    assert_eq!(second.role, Role::User, "subsequent users are regular");
    assert!(!second.is_admin());

    // A duplicate username is rejected, and no second account is created.
    let dup = auth.register("root", "different-pw").await;
    assert!(matches!(dup, Err(Error::Auth(_))), "got {dup:?}");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = 'root'")
        .fetch_one(_db.pool())
        .await
        .unwrap();
    assert_eq!(count, 1, "the duplicate must not have created a second row");
}

// --- 5.4 Wrong-password and unknown-user fail identically; right yields a token

#[tokio::test]
async fn bad_logins_fail_identically_and_good_login_yields_token() {
    let (_db, auth, _dir) = fresh().await;
    auth.register("alice", "s3cret").await.unwrap();

    let wrong_password = auth.login("alice", "nope").await.unwrap_err().to_string();
    let unknown_user = auth.login("ghost", "nope").await.unwrap_err().to_string();
    assert_eq!(
        wrong_password, unknown_user,
        "the error must not reveal whether the username or password was wrong"
    );

    let token = auth.login("alice", "s3cret").await.unwrap();
    assert!(!token.is_empty());
    // ...and the token resolves to the account.
    assert_eq!(auth.authorize(&token).await.unwrap().username, "alice");
}

// --- 5.5 Expired sessions rejected; logout is immediate --------------------

#[tokio::test]
async fn expired_session_is_rejected_by_absolute_and_idle_limits() {
    let (db, auth, _dir) = fresh().await;
    auth.register("alice", "pw").await.unwrap();

    // A zero-hour absolute ceiling expires the session the moment it is checked.
    let expired_absolute = AuthManager::new(db.pool().clone(), &lifetimes(0, 60));
    let token = expired_absolute.login("alice", "pw").await.unwrap();
    assert!(
        matches!(
            expired_absolute.authorize(&token).await,
            Err(Error::Auth(_))
        ),
        "a session past its absolute max must be rejected"
    );

    // A zero-minute idle timeout does the same on the idle axis.
    let expired_idle = AuthManager::new(db.pool().clone(), &lifetimes(24, 0));
    let token = expired_idle.login("alice", "pw").await.unwrap();
    assert!(
        matches!(expired_idle.authorize(&token).await, Err(Error::Auth(_))),
        "an idle-timed-out session must be rejected"
    );
}

#[tokio::test]
async fn logout_invalidates_a_session_immediately() {
    let (_db, auth, _dir) = fresh().await;
    auth.register("alice", "pw").await.unwrap();

    let token = auth.login("alice", "pw").await.unwrap();
    assert!(
        auth.authorize(&token).await.is_ok(),
        "fresh token should work"
    );

    auth.logout(&token).await.unwrap();
    assert!(
        matches!(auth.authorize(&token).await, Err(Error::Auth(_))),
        "the token must not be accepted after logout"
    );
}

// --- 5.6 Ownership / visibility: owner-only + admin-sees-all ----------------

#[tokio::test]
async fn ownership_visibility_owner_admin_and_denial() {
    let (db, auth, _dir) = fresh().await;
    let admin = auth.register("admin", "pw1").await.unwrap();
    let bob = auth.register("bob", "pw2").await.unwrap();
    assert!(admin.is_admin() && !bob.is_admin());

    let t = target("https://api.example.com");
    let admin_session = ScanSession::new(vec![t.clone()], vec!["rest".into()]).with_owner(admin.id);
    let bob_session = ScanSession::new(vec![t.clone()], vec!["cors".into()]).with_owner(bob.id);
    let cli_session = ScanSession::new(vec![t.clone()], vec!["idor".into()]); // no owner
    db.save_session(&admin_session).await.unwrap();
    db.save_session(&bob_session).await.unwrap();
    db.save_session(&cli_session).await.unwrap();

    // A regular user sees only their own session.
    let bob_view = visible_sessions(&db, &bob, 100, 0).await.unwrap();
    assert_eq!(bob_view.len(), 1);
    assert_eq!(bob_view[0].id, bob_session.id);

    // An admin sees every session, including the owner-less CLI one.
    let admin_view = visible_sessions(&db, &admin, 100, 0).await.unwrap();
    assert_eq!(admin_view.len(), 3);

    // The owner can read their own; an admin can read anyone's.
    assert_eq!(
        visible_session(&db, &bob, bob_session.id).await.unwrap().id,
        bob_session.id
    );
    assert_eq!(
        visible_session(&db, &admin, cli_session.id)
            .await
            .unwrap()
            .id,
        cli_session.id
    );

    // A non-owner non-admin is denied a session they do not own.
    let denied = visible_session(&db, &bob, admin_session.id).await;
    assert!(matches!(denied, Err(Error::Auth(_))), "got {denied:?}");
}

#[tokio::test]
async fn owner_stamp_is_immutable_across_re_save() {
    let (db, auth, _dir) = fresh().await;
    let admin = auth.register("admin", "pw1").await.unwrap();
    let bob = auth.register("bob", "pw2").await.unwrap();

    let session = ScanSession::new(vec![target("https://x.example.com")], vec!["rest".into()])
        .with_owner(bob.id);
    db.save_session(&session).await.unwrap();

    // Re-save with a tampered owner and an advanced status.
    let mut tampered = session.clone();
    tampered.owner_user_id = Some(admin.id);
    tampered.status = SessionStatus::Completed;
    db.save_session(&tampered).await.unwrap();

    let reloaded = db.get_session(session.id).await.unwrap().unwrap();
    assert_eq!(
        reloaded.owner_user_id,
        Some(bob.id),
        "the owner stamp must not change on re-save"
    );
    assert_eq!(
        reloaded.status,
        SessionStatus::Completed,
        "other fields still update on re-save"
    );
}

// --- 5.7 Protected functionality denies missing/invalid sessions -----------

#[tokio::test]
async fn guard_denies_missing_or_invalid_tokens_and_admits_valid_ones() {
    let (_db, auth, _dir) = fresh().await;
    auth.register("alice", "pw").await.unwrap();

    // No token, an empty token, and a bogus token are all denied.
    assert!(matches!(auth.guard(None).await, Err(Error::Auth(_))));
    assert!(matches!(auth.guard(Some("")).await, Err(Error::Auth(_))));
    assert!(matches!(
        auth.guard(Some("not-a-real-token")).await,
        Err(Error::Auth(_))
    ));
    // authorize agrees on an unrecognized token.
    assert!(matches!(
        auth.authorize("still-not-real").await,
        Err(Error::Auth(_))
    ));

    // A valid token from a real login is admitted and resolves to the user.
    let token = auth.login("alice", "pw").await.unwrap();
    let user = auth.guard(Some(&token)).await.unwrap();
    assert_eq!(user.username, "alice");
}
