//! Integration tests for the `engagements` capability (h01).
//!
//! Each test runs against a temporary on-disk SQLite file with real registered
//! users. They exercise durable persistence (reload after a "restart"), the
//! reference-only guarantee (associating a scan changes nothing about it), the
//! at-most-one-engagement rule, upload bounds, and per-user visibility.

use abyssum_core::{
    AuthConfig, AuthManager, DocumentKind, EngagementStore, ScanSession, Target, User,
};

/// Open a fresh store plus the auth + engagement authorities over its pool.
async fn fresh() -> (
    AuthManager,
    EngagementStore,
    abyssum_core::DatabaseManager,
    tempfile::TempDir,
) {
    let dir = tempfile::tempdir().unwrap();
    let db = abyssum_core::DatabaseManager::connect(dir.path().join("abyssum.db"))
        .await
        .unwrap();
    let auth = AuthManager::new(db.pool().clone(), &AuthConfig::default());
    let engagements = EngagementStore::from_database(&db);
    (auth, engagements, db, dir)
}

/// Persist a session owned by `owner`.
async fn seed_session(
    db: &abyssum_core::DatabaseManager,
    owner: &User,
    target: &str,
) -> uuid::Uuid {
    let session = ScanSession::new(vec![Target::parse(target).unwrap()], vec!["cors".into()])
        .with_owner(owner.id);
    let id = session.id;
    db.save_session(&session).await.unwrap();
    id
}

// --- An engagement + its documents persist and reload after a restart -------

#[tokio::test]
async fn engagement_and_documents_persist_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("abyssum.db");

    let (owner_id, eid, pdf_doc_id) = {
        let db = abyssum_core::DatabaseManager::connect(&path).await.unwrap();
        let auth = AuthManager::new(db.pool().clone(), &AuthConfig::default());
        let engagements = EngagementStore::from_database(&db);
        let owner = auth.register("owner", "pw").await.unwrap();

        let engagement = engagements
            .create(&owner, "Acme Q3 bug bounty")
            .await
            .unwrap();
        assert_eq!(engagement.owner_user_id, owner.id);

        // One of each kind of document.
        engagements
            .attach_text(&owner, engagement.id, "In scope: *.acme.example")
            .await
            .unwrap();
        engagements
            .attach_url(&owner, engagement.id, "https://acme.example/security")
            .await
            .unwrap();
        let pdf = engagements
            .attach_file(
                &owner,
                engagement.id,
                "auth.pdf",
                b"%PDF-1.7\nsigned",
                1 << 20,
            )
            .await
            .unwrap();

        db.close().await;
        (owner.id, engagement.id, pdf.id)
    };

    // Reopen the store (a process restart) and confirm everything survived.
    let db = abyssum_core::DatabaseManager::connect(&path).await.unwrap();
    let auth = AuthManager::new(db.pool().clone(), &AuthConfig::default());
    let engagements = EngagementStore::from_database(&db);
    let owner = auth.login("owner", "pw").await.unwrap();
    let owner = auth.authorize(&owner).await.unwrap();

    let reloaded = engagements.get_for_user(&owner, eid).await.unwrap();
    assert_eq!(reloaded.name, "Acme Q3 bug bounty");
    assert_eq!(reloaded.owner_user_id, owner_id);

    let docs = engagements.documents(&owner, eid).await.unwrap();
    assert_eq!(docs.len(), 3, "all three documents reloaded");
    assert_eq!(docs[0].kind, DocumentKind::Text);
    assert_eq!(docs[0].content.as_deref(), Some("In scope: *.acme.example"));
    assert_eq!(docs[1].kind, DocumentKind::Url);
    assert_eq!(
        docs[1].content.as_deref(),
        Some("https://acme.example/security")
    );
    assert_eq!(docs[2].kind, DocumentKind::File);

    // The uploaded PDF's bytes reload intact, served as a fixed document type.
    let blob = engagements
        .document_blob(&owner, eid, pdf_doc_id)
        .await
        .unwrap();
    assert_eq!(blob.content_type, "application/pdf");
    assert_eq!(blob.filename, "auth.pdf");
    assert_eq!(blob.bytes, b"%PDF-1.7\nsigned");
}

// --- Associating a scan changes nothing; at most one engagement per scan -----

#[tokio::test]
async fn association_is_reference_only_and_at_most_one() {
    let (auth, engagements, db, _dir) = fresh().await;
    let owner = auth.register("owner", "pw").await.unwrap();

    let a = engagements.create(&owner, "Engagement A").await.unwrap();
    let b = engagements.create(&owner, "Engagement B").await.unwrap();

    // A scan started without an engagement is a valid unassociated session and is
    // in no engagement's list.
    let unassoc = seed_session(&db, &owner, "https://free.example").await;
    assert!(
        engagements
            .sessions_for_engagement(&owner, a.id)
            .await
            .unwrap()
            .is_empty()
    );

    // Associate a scan with A; its targets/scanners are untouched by the association.
    let sid = seed_session(&db, &owner, "https://target.example").await;
    let before = db.get_session(sid).await.unwrap().unwrap();
    engagements
        .assign_session(&owner, Some(a.id), sid)
        .await
        .unwrap();
    let after = db.get_session(sid).await.unwrap().unwrap();
    assert_eq!(
        before.targets, after.targets,
        "targets unchanged by association"
    );
    assert_eq!(
        before.scanner_ids, after.scanner_ids,
        "selected scanners unchanged by association"
    );

    // It shows under A, not under B, and the unassociated scan shows under neither.
    let a_sessions = engagements
        .sessions_for_engagement(&owner, a.id)
        .await
        .unwrap();
    assert_eq!(a_sessions.len(), 1);
    assert_eq!(a_sessions[0].id, sid);
    assert!(!a_sessions.iter().any(|s| s.id == unassoc));

    // Reassigning to B replaces (does not accumulate): now under B only.
    engagements
        .assign_session(&owner, Some(b.id), sid)
        .await
        .unwrap();
    assert!(
        engagements
            .sessions_for_engagement(&owner, a.id)
            .await
            .unwrap()
            .is_empty()
    );
    let b_sessions = engagements
        .sessions_for_engagement(&owner, b.id)
        .await
        .unwrap();
    assert_eq!(b_sessions.len(), 1);
    assert_eq!(b_sessions[0].id, sid);
}

// --- Upload bounds: oversized or disallowed is rejected and not stored -------

#[tokio::test]
async fn oversized_or_disallowed_uploads_are_rejected_and_not_stored() {
    let (auth, engagements, _db, _dir) = fresh().await;
    let owner = auth.register("owner", "pw").await.unwrap();
    let e = engagements.create(&owner, "Bounds").await.unwrap();

    // Oversized: the decoded bytes exceed the per-upload cap.
    assert!(
        engagements
            .attach_file(&owner, e.id, "big.pdf", b"%PDF-toolong", 4)
            .await
            .is_err(),
        "an over-limit upload is rejected"
    );
    // Disallowed type: a PNG (binary, not a PDF, not UTF-8 text).
    assert!(
        engagements
            .attach_file(&owner, e.id, "logo.png", b"\x89PNG\r\n\x1a\n\0\0", 1 << 20)
            .await
            .is_err(),
        "a disallowed type is rejected"
    );

    // Neither was stored: the engagement still has no documents.
    let docs = engagements.documents(&owner, e.id).await.unwrap();
    assert!(docs.is_empty(), "rejected uploads must not be stored");
}

// --- Per-user visibility: non-admin can't see another's; admin can ----------

#[tokio::test]
async fn visibility_is_owner_only_with_admin_override() {
    let (auth, engagements, _db, _dir) = fresh().await;
    let admin = auth.register("admin", "pw").await.unwrap(); // first → admin
    let alice = auth.register("alice", "pw").await.unwrap();
    let bob = auth.register("bob", "pw").await.unwrap();

    let e = engagements
        .create(&alice, "Alice engagement")
        .await
        .unwrap();
    let doc = engagements
        .attach_file(&alice, e.id, "auth.pdf", b"%PDF-1.4 secret", 1 << 20)
        .await
        .unwrap();

    // Bob (non-admin, not authorized) sees nothing of it.
    assert!(engagements.list_for_user(&bob).await.unwrap().is_empty());
    assert!(engagements.get_for_user(&bob, e.id).await.is_err());
    assert!(engagements.documents(&bob, e.id).await.is_err());
    assert!(engagements.document_blob(&bob, e.id, doc.id).await.is_err());

    // Alice (owner/authorized) sees her own.
    assert_eq!(engagements.list_for_user(&alice).await.unwrap().len(), 1);
    assert!(engagements.get_for_user(&alice, e.id).await.is_ok());

    // Admin sees all engagements, including Alice's, and can fetch its documents.
    let all = engagements.list_for_user(&admin).await.unwrap();
    assert!(
        all.iter().any(|x| x.id == e.id),
        "admin sees every engagement"
    );
    assert!(engagements.get_for_user(&admin, e.id).await.is_ok());
    assert!(
        engagements
            .document_blob(&admin, e.id, doc.id)
            .await
            .is_ok()
    );
}
