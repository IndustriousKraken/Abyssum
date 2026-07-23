//! Engagements — a named grouping under which scans are organized and a job's
//! scope / authorization is recorded.
//!
//! Abyssum's premise is *authorized* testing, but the authorization has lived
//! outside the tool. An **engagement** brings it inside: an operator creates a
//! named engagement, associates scans with it, and attaches the job's scope and
//! proof of authorization (pasted text, an external URL, or an uploaded file) for
//! easy reference. It makes the tool's defining claim — that testing was
//! authorized — auditable inside the tool.
//!
//! Two things this module deliberately does **not** do:
//!
//! - **The stored scope never constrains scanning.** It is operator reference
//!   material only; nothing here reads a document to decide what a scan targets or
//!   how a scanner behaves. Machine-enforced scope from freeform bug-bounty text is
//!   unreliable and would give false confidence, so it is out by design.
//! - **No collaboration machinery.** The authorized-operator set is recorded per
//!   engagement (the [`engagement_operators`] table) and today contains exactly the
//!   creator; inviting others later widens that set additively. Provenance — which
//!   operator added each item — is recorded from day one, since it cannot be
//!   backfilled.
//!
//! [`EngagementStore`] is the per-user authority: it enforces visibility on every
//! read and write (an operator sees their own; an `admin` sees all), mirroring
//! [`visible_session`](crate::auth::visible_session). Uploaded file bytes are
//! untrusted, so the served content type is one this module **detects from the
//! bytes** ([`detect_document_type`]), never the client's claim, and is bounded in
//! type and size at attach time.
//!
//! [`engagement_operators`]: crate::persistence

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::auth::{User, visible_session};
use crate::error::{Error, Result, db_err};
use crate::persistence::{DatabaseManager, row_to_session};
use crate::scan::ScanSession;

/// Maximum length of an engagement name (characters, after trimming).
const MAX_NAME_CHARS: usize = 120;

/// Maximum length of pasted scope text (characters). Generous for a bug-bounty
/// scope, bounded so a single paste cannot be unbounded.
const MAX_TEXT_CHARS: usize = 200_000;

/// Maximum length of a stored (sanitized) filename.
const MAX_FILENAME_CHARS: usize = 200;

/// One engagement: a named grouping owned by its creator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Engagement {
    /// Stable per-row id.
    pub id: i64,
    /// The creating operator's id (the initial sole authorized operator).
    pub owner_user_id: i64,
    /// Human-facing name.
    pub name: String,
    /// When the engagement was created.
    pub created_at: DateTime<Utc>,
}

/// How a document's payload is supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentKind {
    /// Pasted scope text, shown inline as text.
    Text,
    /// An external URL, presented as a link the operator follows deliberately.
    Url,
    /// An uploaded file, served safely and (for a PDF) rendered inline.
    File,
}

impl DocumentKind {
    /// The on-disk spelling.
    fn as_str(self) -> &'static str {
        match self {
            DocumentKind::Text => "text",
            DocumentKind::Url => "url",
            DocumentKind::File => "file",
        }
    }

    /// Parse a stored kind, rejecting an unknown value as a store error.
    fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "text" => DocumentKind::Text,
            "url" => DocumentKind::Url,
            "file" => DocumentKind::File,
            other => {
                return Err(Error::Database(format!(
                    "unknown document kind in store: {other:?}"
                )));
            }
        })
    }
}

/// A scope / authorization document's metadata (no file bytes). Text and URL
/// documents carry their payload in `content`; a file's bytes are loaded
/// separately via [`EngagementStore::document_blob`] only when served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngagementDocument {
    /// Stable per-row id.
    pub id: i64,
    /// The engagement this document belongs to.
    pub engagement_id: i64,
    /// How the payload was supplied.
    pub kind: DocumentKind,
    /// The pasted text or the URL; `None` for a file (bytes are stored separately).
    pub content: Option<String>,
    /// The served content type for a file (detected from the bytes); `None`
    /// otherwise.
    pub content_type: Option<String>,
    /// The sanitized original filename for a file; `None` otherwise.
    pub filename: Option<String>,
    /// Provenance: which operator attached the document.
    pub added_by_user_id: i64,
    /// When it was attached.
    pub added_at: DateTime<Utc>,
}

/// An uploaded file's bytes plus the metadata needed to serve it safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentBlob {
    /// The content type the engine detected from the bytes (never the client's
    /// claim, never `text/html`).
    pub content_type: String,
    /// The sanitized filename, safe for a `Content-Disposition` header.
    pub filename: String,
    /// The stored file bytes.
    pub bytes: Vec<u8>,
}

/// Detect an uploaded file's type from its bytes, returning the content type to
/// serve it as, or `None` if the type is not allowed.
///
/// The allowlist is intentionally small — a PDF (the usual signed authorization)
/// or plain UTF-8 text — and is decided from the **bytes**, not the client's
/// declared type, so a lying `Content-Type` cannot get a file stored or served as
/// something it is not. A PDF is recognized by its `%PDF-` signature; anything
/// that is valid UTF-8 without a NUL byte is treated as text; everything else is
/// rejected. Pure, so it is unit-testable without a database.
pub fn detect_document_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"%PDF-") {
        return Some("application/pdf");
    }
    // "Looks like text": valid UTF-8 with no NUL byte. This is what lets a plain
    // scope .txt through while rejecting arbitrary binary (a PNG, an executable).
    if !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok() {
        return Some("text/plain; charset=utf-8");
    }
    None
}

/// The per-user engagement authority over the shared store. Cheap to clone (the
/// inner [`DatabaseManager`] is a reference-counted pool).
#[derive(Debug, Clone)]
pub struct EngagementStore {
    db: DatabaseManager,
}

impl EngagementStore {
    /// Build over a [`DatabaseManager`] (already migrated after
    /// [`DatabaseManager::connect`]).
    pub fn from_database(db: &DatabaseManager) -> Self {
        Self { db: db.clone() }
    }

    // --- Engagements ------------------------------------------------------

    /// Create an engagement named `name`, owned by `creator`, and initialize its
    /// authorized-operator set to exactly the creator. The name is trimmed and must
    /// be non-empty and bounded in length.
    pub async fn create(&self, creator: &User, name: &str) -> Result<Engagement> {
        let name = validate_name(name)?;
        let now = Utc::now();
        let mut tx = self.db.pool().begin().await.map_err(db_err)?;
        let id = sqlx::query(
            "INSERT INTO engagements (owner_user_id, name, created_at) VALUES (?, ?, ?)",
        )
        .bind(creator.id)
        .bind(&name)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?
        .last_insert_rowid();
        // The authorized set starts as exactly the creator (the collaboration seam).
        sqlx::query("INSERT INTO engagement_operators (engagement_id, user_id) VALUES (?, ?)")
            .bind(id)
            .bind(creator.id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(Engagement {
            id,
            owner_user_id: creator.id,
            name,
            created_at: now,
        })
    }

    /// The engagements `viewer` may see: every engagement for an `admin`, otherwise
    /// only those the viewer is an authorized operator for (today, the ones they
    /// created). Most-recently-created first.
    pub async fn list_for_user(&self, viewer: &User) -> Result<Vec<Engagement>> {
        let rows = if viewer.is_admin() {
            sqlx::query(
                "SELECT id, owner_user_id, name, created_at FROM engagements ORDER BY id DESC",
            )
            .fetch_all(self.db.pool())
            .await
            .map_err(db_err)?
        } else {
            sqlx::query(
                "SELECT e.id, e.owner_user_id, e.name, e.created_at \
                 FROM engagements e \
                 JOIN engagement_operators o ON o.engagement_id = e.id \
                 WHERE o.user_id = ? ORDER BY e.id DESC",
            )
            .bind(viewer.id)
            .fetch_all(self.db.pool())
            .await
            .map_err(db_err)?
        };
        rows.iter().map(row_to_engagement).collect()
    }

    /// One engagement, enforcing visibility: an authorized operator or an `admin`
    /// gets it; anyone else — and a missing id — is denied with [`Error::Auth`],
    /// disclosing nothing. This is the gate every engagement-scoped read/write goes
    /// through.
    pub async fn get_for_user(&self, viewer: &User, id: i64) -> Result<Engagement> {
        let row =
            sqlx::query("SELECT id, owner_user_id, name, created_at FROM engagements WHERE id = ?")
                .bind(id)
                .fetch_optional(self.db.pool())
                .await
                .map_err(db_err)?;
        match row {
            Some(row) if viewer.is_admin() || self.is_operator(viewer.id, id).await? => {
                row_to_engagement(&row)
            }
            _ => Err(Error::Auth("engagement not found".to_string())),
        }
    }

    /// Whether `user_id` is in engagement `id`'s authorized-operator set.
    async fn is_operator(&self, user_id: i64, id: i64) -> Result<bool> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM engagement_operators WHERE engagement_id = ? AND user_id = ?",
        )
        .bind(id)
        .bind(user_id)
        .fetch_one(self.db.pool())
        .await
        .map_err(db_err)?;
        Ok(count > 0)
    }

    // --- Documents --------------------------------------------------------

    /// Attach pasted scope text to an engagement `viewer` may edit. The text is
    /// trimmed and must be non-empty and bounded in length.
    pub async fn attach_text(
        &self,
        viewer: &User,
        engagement_id: i64,
        text: &str,
    ) -> Result<EngagementDocument> {
        self.get_for_user(viewer, engagement_id).await?; // visibility gate
        let text = text.trim();
        if text.is_empty() {
            return Err(Error::Other("scope text is required".to_string()));
        }
        if text.chars().count() > MAX_TEXT_CHARS {
            return Err(Error::Other("scope text is too long".to_string()));
        }
        self.insert_document(
            engagement_id,
            DocumentKind::Text,
            Some(text),
            None,
            None,
            None,
            viewer.id,
        )
        .await
    }

    /// Attach an external scope URL to an engagement `viewer` may edit. The URL must
    /// parse as an absolute `http`/`https` URL — anything else (e.g. a `javascript:`
    /// or `data:` URL that could execute when rendered as a link) is rejected.
    pub async fn attach_url(
        &self,
        viewer: &User,
        engagement_id: i64,
        url: &str,
    ) -> Result<EngagementDocument> {
        self.get_for_user(viewer, engagement_id).await?; // visibility gate
        let url = url.trim();
        let parsed = url::Url::parse(url)
            .map_err(|_| Error::Other("scope URL is not a valid URL".to_string()))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(Error::Other(
                "scope URL must be an http or https URL".to_string(),
            ));
        }
        self.insert_document(
            engagement_id,
            DocumentKind::Url,
            Some(url),
            None,
            None,
            None,
            viewer.id,
        )
        .await
    }

    /// Attach an uploaded file to an engagement `viewer` may edit. The upload is
    /// bounded: its decoded byte length must not exceed `max_bytes`, and its type
    /// must be one [`detect_document_type`] allows (PDF or plain text) — an
    /// over-limit or disallowed upload is rejected with a clear error and **not**
    /// stored. The served content type is the detected one, never the client's
    /// claim.
    pub async fn attach_file(
        &self,
        viewer: &User,
        engagement_id: i64,
        filename: &str,
        bytes: &[u8],
        max_bytes: usize,
    ) -> Result<EngagementDocument> {
        self.get_for_user(viewer, engagement_id).await?; // visibility gate
        if bytes.is_empty() {
            return Err(Error::Other("uploaded file is empty".to_string()));
        }
        if bytes.len() > max_bytes {
            return Err(Error::Other(format!(
                "uploaded file is too large (max {max_bytes} bytes)"
            )));
        }
        let content_type = detect_document_type(bytes).ok_or_else(|| {
            Error::Other(
                "unsupported document type — upload a PDF or a plain-text file".to_string(),
            )
        })?;
        let filename = sanitize_filename(filename);
        self.insert_document(
            engagement_id,
            DocumentKind::File,
            None,
            Some(bytes),
            Some(content_type),
            Some(&filename),
            viewer.id,
        )
        .await
    }

    /// Insert a document row and return its metadata (shared by the three attach
    /// paths). The caller has already run the visibility gate and validated inputs.
    #[allow(clippy::too_many_arguments)]
    async fn insert_document(
        &self,
        engagement_id: i64,
        kind: DocumentKind,
        content: Option<&str>,
        blob: Option<&[u8]>,
        content_type: Option<&str>,
        filename: Option<&str>,
        added_by_user_id: i64,
    ) -> Result<EngagementDocument> {
        let now = Utc::now();
        let id = sqlx::query(
            "INSERT INTO engagement_documents \
               (engagement_id, kind, content, blob, content_type, filename, added_by_user_id, added_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(engagement_id)
        .bind(kind.as_str())
        .bind(content)
        .bind(blob)
        .bind(content_type)
        .bind(filename)
        .bind(added_by_user_id)
        .bind(now)
        .execute(self.db.pool())
        .await
        .map_err(db_err)?
        .last_insert_rowid();
        Ok(EngagementDocument {
            id,
            engagement_id,
            kind,
            content: content.map(str::to_string),
            content_type: content_type.map(str::to_string),
            filename: filename.map(str::to_string),
            added_by_user_id,
            added_at: now,
        })
    }

    /// Every document attached to an engagement `viewer` may see, oldest first (so
    /// the scope reads in the order it was assembled). Metadata only — a file's
    /// bytes are loaded separately by [`document_blob`](Self::document_blob).
    pub async fn documents(
        &self,
        viewer: &User,
        engagement_id: i64,
    ) -> Result<Vec<EngagementDocument>> {
        self.get_for_user(viewer, engagement_id).await?; // visibility gate
        let rows = sqlx::query(
            "SELECT id, engagement_id, kind, content, content_type, filename, \
                    added_by_user_id, added_at \
             FROM engagement_documents WHERE engagement_id = ? ORDER BY id ASC",
        )
        .bind(engagement_id)
        .fetch_all(self.db.pool())
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_document).collect()
    }

    /// Load one file document's bytes for serving, enforcing visibility. A document
    /// of another engagement, a non-file document, or an absent id all yield
    /// [`Error::Auth`] (`viewer` may not see it), disclosing nothing.
    pub async fn document_blob(
        &self,
        viewer: &User,
        engagement_id: i64,
        document_id: i64,
    ) -> Result<DocumentBlob> {
        self.get_for_user(viewer, engagement_id).await?; // visibility gate
        let row = sqlx::query(
            "SELECT blob, content_type, filename FROM engagement_documents \
             WHERE id = ? AND engagement_id = ? AND kind = 'file'",
        )
        .bind(document_id)
        .bind(engagement_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(db_err)?;
        use sqlx::Row;
        match row {
            Some(row) => Ok(DocumentBlob {
                content_type: row
                    .try_get::<Option<String>, _>("content_type")
                    .map_err(db_err)?
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
                filename: row
                    .try_get::<Option<String>, _>("filename")
                    .map_err(db_err)?
                    .unwrap_or_else(|| "document".to_string()),
                bytes: row
                    .try_get::<Option<Vec<u8>>, _>("blob")
                    .map_err(db_err)?
                    .unwrap_or_default(),
            }),
            None => Err(Error::Auth("document not found".to_string())),
        }
    }

    // --- Scan association -------------------------------------------------

    /// Associate a scan session with an engagement (or clear its association when
    /// `engagement_id` is `None`). Both the engagement (when set) and the session
    /// must be visible to `assigner`; the association records who made it. Because
    /// the session carries a single engagement column, a reassignment replaces the
    /// previous one rather than accumulating.
    pub async fn assign_session(
        &self,
        assigner: &User,
        engagement_id: Option<i64>,
        session_id: Uuid,
    ) -> Result<()> {
        // The assigner must be able to act on the session (owner or admin).
        visible_session(&self.db, assigner, session_id).await?;
        // ...and, when associating, be authorized for the target engagement.
        if let Some(eid) = engagement_id {
            self.get_for_user(assigner, eid).await?;
        }
        sqlx::query(
            "UPDATE sessions SET engagement_id = ?, engagement_assigned_by = ? \
             WHERE session_id = ?",
        )
        .bind(engagement_id)
        .bind(engagement_id.map(|_| assigner.id))
        .bind(session_id.to_string())
        .execute(self.db.pool())
        .await
        .map_err(db_err)?;
        Ok(())
    }

    /// The scan sessions associated with an engagement `viewer` may see, most
    /// recent first (metadata only, empty findings — like
    /// [`DatabaseManager::list_sessions`]).
    pub async fn sessions_for_engagement(
        &self,
        viewer: &User,
        engagement_id: i64,
    ) -> Result<Vec<ScanSession>> {
        self.get_for_user(viewer, engagement_id).await?; // visibility gate
        let rows = sqlx::query(
            "SELECT session_id, status, targets_json, scanners_json, error_count, \
                    completed_units, total_units, started_at, finished_at, owner_user_id \
             FROM sessions WHERE engagement_id = ? ORDER BY created_at DESC, id DESC",
        )
        .bind(engagement_id)
        .fetch_all(self.db.pool())
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_session).collect()
    }
}

/// Trim + validate an engagement name: non-empty after trimming, bounded length.
fn validate_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::Other("engagement name is required".to_string()));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(Error::Other(format!(
            "engagement name is too long (max {MAX_NAME_CHARS} characters)"
        )));
    }
    Ok(name.to_string())
}

/// Reduce an operator-supplied filename to a safe basename: drop any path, strip
/// characters that could break a `Content-Disposition` header (quotes, control
/// bytes, path separators), keep only ASCII, and bound the length. An empty result
/// becomes `"document"`. The stored filename is display/download metadata only —
/// the served content type is decided from the bytes, not this name. Non-ASCII is
/// dropped because the header value is emitted through `HeaderValue`, which accepts
/// visible ASCII only; a non-ASCII byte there would fail conversion and 500 the
/// serve, so a name kept here is guaranteed header-safe.
fn sanitize_filename(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let cleaned: String = base
        .chars()
        .filter(|c| c.is_ascii() && !c.is_control() && *c != '"' && *c != '\\')
        .take(MAX_FILENAME_CHARS)
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        "document".to_string()
    } else {
        cleaned.to_string()
    }
}

/// Map an `engagements` row into an [`Engagement`].
fn row_to_engagement(row: &sqlx::sqlite::SqliteRow) -> Result<Engagement> {
    use sqlx::Row;
    Ok(Engagement {
        id: row.try_get("id").map_err(db_err)?,
        owner_user_id: row.try_get("owner_user_id").map_err(db_err)?,
        name: row.try_get("name").map_err(db_err)?,
        created_at: row.try_get("created_at").map_err(db_err)?,
    })
}

/// Map an `engagement_documents` metadata row into an [`EngagementDocument`].
fn row_to_document(row: &sqlx::sqlite::SqliteRow) -> Result<EngagementDocument> {
    use sqlx::Row;
    Ok(EngagementDocument {
        id: row.try_get("id").map_err(db_err)?,
        engagement_id: row.try_get("engagement_id").map_err(db_err)?,
        kind: DocumentKind::parse(&row.try_get::<String, _>("kind").map_err(db_err)?)?,
        content: row.try_get("content").map_err(db_err)?,
        content_type: row.try_get("content_type").map_err(db_err)?,
        filename: row.try_get("filename").map_err(db_err)?,
        added_by_user_id: row.try_get("added_by_user_id").map_err(db_err)?,
        added_at: row.try_get("added_at").map_err(db_err)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_allows_pdf_and_text_rejects_binary() {
        assert_eq!(
            detect_document_type(b"%PDF-1.7\n..."),
            Some("application/pdf")
        );
        assert_eq!(
            detect_document_type("in scope: *.example.com".as_bytes()),
            Some("text/plain; charset=utf-8")
        );
        // A PNG (binary, has a NUL, invalid UTF-8) is not an allowed document type.
        assert_eq!(detect_document_type(b"\x89PNG\r\n\x1a\n\0\0"), None);
        // Arbitrary bytes with a NUL are rejected even if the prefix looks textual.
        assert_eq!(detect_document_type(b"scope\0hidden"), None);
    }

    #[test]
    fn name_validation_trims_and_bounds() {
        assert_eq!(validate_name("  Acme Q3  ").unwrap(), "Acme Q3");
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"x".repeat(MAX_NAME_CHARS + 1)).is_err());
    }

    #[test]
    fn filename_is_reduced_to_a_safe_basename() {
        assert_eq!(sanitize_filename("/etc/../auth.pdf"), "auth.pdf");
        assert_eq!(sanitize_filename("C:\\jobs\\scope.txt"), "scope.txt");
        // Quotes and control bytes that could break the header are stripped.
        assert_eq!(sanitize_filename("a\"b\r\n.txt"), "ab.txt");
        // Non-ASCII is dropped (HeaderValue is ASCII-only): the remaining ASCII is
        // kept, and a name that is entirely non-ASCII falls back to the default.
        assert_eq!(sanitize_filename("café.pdf"), "caf.pdf");
        assert_eq!(sanitize_filename("авторизация"), "document");
        // An empty / all-stripped name falls back to a fixed default.
        assert_eq!(sanitize_filename("   "), "document");
        assert_eq!(sanitize_filename(""), "document");
    }

    #[test]
    fn document_kind_strings_round_trip() {
        for kind in [DocumentKind::Text, DocumentKind::Url, DocumentKind::File] {
            assert_eq!(DocumentKind::parse(kind.as_str()).unwrap(), kind);
        }
        assert!(matches!(
            DocumentKind::parse("bogus"),
            Err(Error::Database(_))
        ));
    }
}
