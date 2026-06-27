//! Integration tests for the `annotations` capability (d00).
//!
//! Every test runs against a temporary on-disk SQLite file in its own temp dir
//! (the same store the persistence/auth tests use). No network, no real targets —
//! all data is synthetic. Ownership is exercised with real registered users.

use abyssum_core::{
    AnnotationStore, AuthConfig, AuthManager, DatabaseManager, Error, Finding, FindingId, Severity,
    Status, TagApply, Target,
};
use uuid::Uuid;

/// Open a fresh store plus the auth + annotation authorities over its pool.
async fn fresh() -> (
    DatabaseManager,
    AuthManager,
    AnnotationStore,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let db = DatabaseManager::connect(dir.path().join("abyssum.db"))
        .await
        .unwrap();
    let auth = AuthManager::new(db.pool().clone(), &AuthConfig::default());
    let notes = AnnotationStore::from_database(&db);
    (db, auth, notes, dir)
}

fn target(url: &str) -> Target {
    Target::parse(url).unwrap()
}

/// Persist a session owned by `owner` and return its id.
async fn owned_session(db: &DatabaseManager, owner: i64, url: &str) -> Uuid {
    let session =
        abyssum_core::ScanSession::new(vec![target(url)], vec!["cors".into()]).with_owner(owner);
    let id = session.id;
    db.save_session(&session).await.unwrap();
    id
}

/// Save a finding under `session_id` and return its assigned stable id.
async fn save_finding(db: &DatabaseManager, session_id: Uuid, url: &str, title: &str) -> FindingId {
    let finding: Finding = Finding::builder("cors", target(url), title)
        .severity(Severity::High)
        .status(Status::Vulnerable)
        .build();
    db.save_finding(session_id, &finding).await.unwrap()
}

// --- 7.2 Notes: add / edit / delete on a session and a finding --------------

#[tokio::test]
async fn session_note_add_edit_delete_round_trip() {
    let (db, auth, notes, _dir) = fresh().await;
    let alice = auth.register("alice", "pw").await.unwrap();
    let sid = owned_session(&db, alice.id, "https://a.test").await;

    // Empty / whitespace-only content is rejected and stores nothing.
    assert!(notes.add_note(&alice, sid, None, "   ").await.is_err());
    assert!(notes.session_notes(&alice, sid).await.unwrap().is_empty());

    // A valid note is stored, trimmed, and stamps author + creation time.
    let note = notes
        .add_note(&alice, sid, None, "  triaged: looks exploitable  ")
        .await
        .unwrap();
    assert_eq!(note.content, "triaged: looks exploitable");
    assert_eq!(note.author, "alice");
    assert!(note.edited_at.is_none());

    // Editing updates content and records that it was edited; an empty edit is
    // rejected and leaves the content unchanged.
    assert!(notes.edit_note(&alice, note.id, "  ").await.is_err());
    let edited = notes
        .edit_note(&alice, note.id, "confirmed exploitable")
        .await
        .unwrap();
    assert_eq!(edited.content, "confirmed exploitable");
    assert!(edited.edited_at.is_some());
    let reread = &notes.session_notes(&alice, sid).await.unwrap()[0];
    assert_eq!(reread.content, "confirmed exploitable");

    // Deleting removes it; a second note on the session is unaffected.
    let keep = notes.add_note(&alice, sid, None, "keep me").await.unwrap();
    notes.delete_note(&alice, note.id).await.unwrap();
    let remaining = notes.session_notes(&alice, sid).await.unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, keep.id);
}

#[tokio::test]
async fn finding_note_is_scoped_to_its_finding() {
    let (db, auth, notes, _dir) = fresh().await;
    let alice = auth.register("alice", "pw").await.unwrap();
    let sid = owned_session(&db, alice.id, "https://a.test").await;
    let fid = save_finding(&db, sid, "https://a.test/x", "Exposed endpoint").await;

    // A finding note is retrievable as the finding's notes...
    let fnote = notes
        .add_note(&alice, sid, Some(fid), "this one needs a writeup")
        .await
        .unwrap();
    assert_eq!(fnote.finding_id, Some(fid));
    let listed = notes.finding_notes(&alice, sid, fid).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, fnote.id);

    // ...and does not show up among the session-level notes.
    assert!(notes.session_notes(&alice, sid).await.unwrap().is_empty());

    // A note targeting a finding that does not belong to the session is rejected.
    let other_sid = owned_session(&db, alice.id, "https://b.test").await;
    assert!(notes
        .add_note(&alice, other_sid, Some(fid), "wrong session")
        .await
        .is_err());
}

#[tokio::test]
async fn note_on_unknown_session_is_reported_not_found() {
    let (_db, auth, notes, _dir) = fresh().await;
    let alice = auth.register("alice", "pw").await.unwrap();
    let unknown = Uuid::new_v4();
    let err = notes.add_note(&alice, unknown, None, "hi").await;
    assert!(matches!(err, Err(Error::Auth(_))), "got {err:?}");
}

// --- 7.3 Tags: apply / remove, auto-create, no duplicate application --------

#[tokio::test]
async fn apply_remove_autocreate_and_no_duplicate_application() {
    let (db, auth, notes, _dir) = fresh().await;
    let alice = auth.register("alice", "pw").await.unwrap();
    let sid = owned_session(&db, alice.id, "https://a.test").await;

    // Applying an unknown name auto-creates the tag and applies it.
    notes
        .apply_tags(
            &alice,
            sid,
            &[TagApply::with_color("Auth-Bypass", "#ff0000")],
        )
        .await
        .unwrap();
    let applied = notes.session_tags(&alice, sid).await.unwrap();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].name, "auth-bypass"); // normalized
    assert_eq!(applied[0].color, "#ff0000");

    // Re-applying the same tag (any case) does not duplicate it.
    notes
        .apply_tags(&alice, sid, &[TagApply::new("auth-bypass")])
        .await
        .unwrap();
    assert_eq!(notes.session_tags(&alice, sid).await.unwrap().len(), 1);

    // A name with no color auto-creates with the default color.
    notes
        .apply_tags(&alice, sid, &[TagApply::new("needs-writeup")])
        .await
        .unwrap();
    let writeup = notes
        .session_tags(&alice, sid)
        .await
        .unwrap()
        .into_iter()
        .find(|t| t.name == "needs-writeup")
        .unwrap();
    assert_eq!(writeup.color, abyssum_core::DEFAULT_TAG_COLOR);

    // Removing a tag drops the application but keeps the shared tag definition.
    let auth_bypass_id = applied[0].id;
    notes.remove_tag(&alice, sid, auth_bypass_id).await.unwrap();
    let after = notes.session_tags(&alice, sid).await.unwrap();
    assert!(after.iter().all(|t| t.name != "auth-bypass"));
    // The tag still exists globally (usage count now zero).
    let usage = notes.list_tags().await.unwrap();
    assert!(usage.iter().any(|u| u.tag.name == "auth-bypass"));
}

#[tokio::test]
async fn explicit_create_rejects_duplicate_and_bad_color() {
    let (_db, _auth, notes, _dir) = fresh().await;

    notes
        .create_tag("idor", Some("#112233"), Some("access-control"))
        .await
        .unwrap();
    // A second create with the same normalized name is rejected.
    assert!(notes
        .create_tag("IDOR", Some("#445566"), None)
        .await
        .is_err());
    // A malformed color is rejected.
    assert!(notes.create_tag("ssrf", Some("red"), None).await.is_err());
    // Only the one tag exists.
    let tags = notes.list_tags().await.unwrap();
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].tag.name, "idor");
}

// --- 7.4 list_tags usage counts; deleting a session cleans up annotations ---

#[tokio::test]
async fn list_tags_usage_counts_and_session_delete_cleanup() {
    let (db, auth, notes, _dir) = fresh().await;
    let alice = auth.register("alice", "pw").await.unwrap();
    let s1 = owned_session(&db, alice.id, "https://1.test").await;
    let s2 = owned_session(&db, alice.id, "https://2.test").await;

    // `shared` is applied to both sessions; `solo` to only one.
    notes
        .apply_tags(
            &alice,
            s1,
            &[TagApply::new("shared"), TagApply::new("solo")],
        )
        .await
        .unwrap();
    notes
        .apply_tags(&alice, s2, &[TagApply::new("shared")])
        .await
        .unwrap();
    notes
        .add_note(&alice, s1, None, "a note on s1")
        .await
        .unwrap();

    let usage = notes.list_tags().await.unwrap();
    let count = |name: &str| {
        usage
            .iter()
            .find(|u| u.tag.name == name)
            .unwrap()
            .session_count
    };
    assert_eq!(count("shared"), 2);
    assert_eq!(count("solo"), 1);

    // Deleting s1 removes its notes and tag applications, but leaves the shared
    // tag definitions intact (and `shared`'s count drops to 1, `solo` to 0).
    assert!(db.delete_session(s1).await.unwrap());
    let notes_left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notes WHERE session_id = ?")
        .bind(s1.to_string())
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(notes_left, 0);
    let apps_left: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM session_tags WHERE session_id = ?")
            .bind(s1.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(apps_left, 0);

    let usage = notes.list_tags().await.unwrap();
    assert_eq!(
        usage.len(),
        2,
        "shared definitions survive the session delete"
    );
    let count = |name: &str| {
        usage
            .iter()
            .find(|u| u.tag.name == name)
            .unwrap()
            .session_count
    };
    assert_eq!(count("shared"), 1);
    assert_eq!(count("solo"), 0);
}

// --- 7.5 Note substring search; tag match-all vs match-any ------------------

#[tokio::test]
async fn note_search_and_tag_filter_modes() {
    let (db, auth, notes, _dir) = fresh().await;
    let alice = auth.register("alice", "pw").await.unwrap();
    let s_a = owned_session(&db, alice.id, "https://a.test").await;
    let s_b = owned_session(&db, alice.id, "https://b.test").await;
    let s_c = owned_session(&db, alice.id, "https://c.test").await;

    notes
        .add_note(&alice, s_a, None, "SQL injection on the login form")
        .await
        .unwrap();
    notes
        .add_note(&alice, s_b, None, "permissive CORS, no injection here yet")
        .await
        .unwrap();
    notes
        .add_note(&alice, s_c, None, "nothing notable")
        .await
        .unwrap();

    // Substring search returns only sessions whose notes contain the term.
    let hits = notes
        .search_sessions_by_note(&alice, "injection")
        .await
        .unwrap();
    let ids: Vec<Uuid> = hits.iter().map(|s| s.id).collect();
    assert!(ids.contains(&s_a) && ids.contains(&s_b));
    assert!(!ids.contains(&s_c));

    // Tag filter: s_a carries {x, y}; s_b carries {x}; s_c carries {y}.
    notes
        .apply_tags(&alice, s_a, &[TagApply::new("x"), TagApply::new("y")])
        .await
        .unwrap();
    notes
        .apply_tags(&alice, s_b, &[TagApply::new("x")])
        .await
        .unwrap();
    notes
        .apply_tags(&alice, s_c, &[TagApply::new("y")])
        .await
        .unwrap();

    // Match-any {x, y} → every session carrying at least one (all three).
    let any = notes
        .filter_sessions_by_tags(&alice, &["x".into(), "y".into()], false)
        .await
        .unwrap();
    assert_eq!(any.len(), 3);

    // Match-all {x, y} → only the session carrying both (s_a).
    let all = notes
        .filter_sessions_by_tags(&alice, &["x".into(), "y".into()], true)
        .await
        .unwrap();
    let all_ids: Vec<Uuid> = all.iter().map(|s| s.id).collect();
    assert_eq!(all_ids, vec![s_a]);

    // Match-all including a tag nobody carries → empty.
    let none = notes
        .filter_sessions_by_tags(&alice, &["x".into(), "ghost".into()], true)
        .await
        .unwrap();
    assert!(none.is_empty());
}

// --- 7.6 Ownership: non-owner denied; admin reads/writes + searches all -----

#[tokio::test]
async fn ownership_is_enforced_and_admin_spans_owners() {
    let (db, auth, notes, _dir) = fresh().await;
    let admin = auth.register("admin", "pw").await.unwrap(); // first → admin
    let alice = auth.register("alice", "pw").await.unwrap();
    let bob = auth.register("bob", "pw").await.unwrap();
    assert!(admin.is_admin() && !alice.is_admin() && !bob.is_admin());

    let alice_sid = owned_session(&db, alice.id, "https://alice.test").await;
    let bob_sid = owned_session(&db, bob.id, "https://bob.test").await;
    let note = notes
        .add_note(&alice, alice_sid, None, "alice-only secret detail")
        .await
        .unwrap();
    notes
        .add_note(&bob, bob_sid, None, "bob secret detail")
        .await
        .unwrap();

    // A non-owner non-admin cannot read, write, edit, delete, or tag.
    assert!(deny(notes.session_notes(&bob, alice_sid).await));
    assert!(deny(
        notes.add_note(&bob, alice_sid, None, "intruder").await
    ));
    assert!(deny(notes.edit_note(&bob, note.id, "hijacked").await));
    assert!(deny(notes.delete_note(&bob, note.id).await));
    assert!(deny(
        notes
            .apply_tags(&bob, alice_sid, &[TagApply::new("x")])
            .await
    ));

    // The owner may act on their own session.
    assert!(notes.session_notes(&alice, alice_sid).await.is_ok());

    // An admin may read and write any session...
    assert_eq!(
        notes.session_notes(&admin, alice_sid).await.unwrap().len(),
        1
    );
    notes
        .add_note(&admin, alice_sid, None, "admin annotation")
        .await
        .unwrap();

    // ...and a search/filter spans all owners for an admin but is owner-scoped
    // for a regular user.
    let alice_view = notes
        .search_sessions_by_note(&alice, "secret detail")
        .await
        .unwrap();
    let alice_ids: Vec<Uuid> = alice_view.iter().map(|s| s.id).collect();
    assert!(alice_ids.contains(&alice_sid) && !alice_ids.contains(&bob_sid));

    let admin_view = notes
        .search_sessions_by_note(&admin, "secret detail")
        .await
        .unwrap();
    let admin_ids: Vec<Uuid> = admin_view.iter().map(|s| s.id).collect();
    assert!(admin_ids.contains(&alice_sid) && admin_ids.contains(&bob_sid));
}

/// Whether a result is an authorization denial.
fn deny<T>(result: Result<T, Error>) -> bool {
    matches!(result, Err(Error::Auth(_)))
}
