//! Annotations: freeform notes on sessions and findings, plus reusable
//! color-coded tags applied to sessions.
//!
//! This is metadata layered over the persisted `sessions`/`findings` from
//! `add-result-persistence`. It owns three tables (added by the `0004`
//! migration): `notes`, `tags`, and the `session_tags` join.
//!
//! ## Ownership follows the parent session
//!
//! A note and a tag-application inherit the owner of the session they decorate.
//! Every read/write gates through [`visible_session`](crate::auth::visible_session)
//! — the same owner-or-`admin` check the rest of the surface uses — so the
//! annotation layer never widens visibility beyond what the underlying session
//! allows. The store proper stays ownership-blind; this module applies the gate,
//! mirroring how [`auth`](crate::auth) layers scoping over
//! [`persistence`](crate::persistence).
//!
//! ## Tags are global, applications are per-session
//!
//! A [`Tag`] (name + color + description) is shared across the instance; what is
//! owned is its *application* to a session. Names are normalized (trimmed,
//! lower-cased) so `Auth-Bypass` and `auth-bypass` are the same tag and never
//! duplicate. Applying a tag by a name that does not yet exist creates it (with a
//! supplied color or the neutral-gray [`DEFAULT_TAG_COLOR`]), then applies it.

use chrono::{DateTime, Utc};
use sqlx::sqlite::SqliteRow;
use sqlx::{QueryBuilder, Row, Sqlite};
use uuid::Uuid;

use crate::auth::{visible_session, User};
use crate::error::{db_err, Error, Result};
use crate::persistence::{escape_like, row_to_session, DatabaseManager, DEFAULT_SEARCH_LIMIT};
use crate::scan::{FindingId, ScanSession};

/// The default tag color (neutral gray) assigned when a tag is created without an
/// explicit color — including the implicit create on the apply-by-name path.
pub const DEFAULT_TAG_COLOR: &str = "#6B7280";

/// A freeform note attached to a session (and optionally to one finding in it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// Stable primary key.
    pub id: i64,
    /// The session the note decorates.
    pub session_id: Uuid,
    /// The finding within that session, for a finding-level note; `None` for a
    /// session-level note.
    pub finding_id: Option<FindingId>,
    /// The note text (trimmed, never empty).
    pub content: String,
    /// The username that wrote the note.
    pub author: String,
    /// When the note was created.
    pub created_at: DateTime<Utc>,
    /// When the note was last edited, if ever.
    pub edited_at: Option<DateTime<Utc>>,
}

/// A reusable, color-coded tag. Global across the instance; applied to sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    /// Stable primary key.
    pub id: i64,
    /// The normalized (trimmed, lower-cased) unique name.
    pub name: String,
    /// The hex color (`#RRGGBB`).
    pub color: String,
    /// An optional free-text description.
    pub description: Option<String>,
}

/// A tag together with the number of sessions it is applied to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagUsage {
    /// The tag.
    pub tag: Tag,
    /// How many sessions currently carry it.
    pub session_count: i64,
}

/// A tag to apply to a session: a name plus an optional color used *only* when
/// the tag must be created (an existing tag keeps its color).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagApply {
    /// The tag name (normalized on use).
    pub name: String,
    /// The color to give the tag if it is created now; ignored if it exists.
    pub color: Option<String>,
}

impl TagApply {
    /// Apply by name, defaulting the color if the tag is created.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            color: None,
        }
    }

    /// Apply by name, giving an explicit color if the tag is created now.
    pub fn with_color(name: impl Into<String>, color: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            color: Some(color.into()),
        }
    }
}

/// The annotation authority over the shared store. Cheap to clone (the inner
/// [`DatabaseManager`] is a reference-counted pool).
#[derive(Debug, Clone)]
pub struct AnnotationStore {
    db: DatabaseManager,
}

impl AnnotationStore {
    /// Build over a [`DatabaseManager`] (the store must already be migrated, which
    /// it is after [`DatabaseManager::connect`]).
    pub fn new(db: DatabaseManager) -> Self {
        Self { db }
    }

    /// Build over a borrowed [`DatabaseManager`], cloning its pool handle.
    pub fn from_database(db: &DatabaseManager) -> Self {
        Self { db: db.clone() }
    }

    // --- Notes ------------------------------------------------------------

    /// Add a note to a session (`finding_id == None`) or to a finding within it.
    /// Gated on session ownership; an unknown session is reported as not found,
    /// a finding not belonging to the named session is rejected, and empty or
    /// whitespace-only content is rejected — no note is stored in any of those
    /// cases. The author and creation time are stamped on the stored note.
    pub async fn add_note(
        &self,
        user: &User,
        session_id: Uuid,
        finding_id: Option<FindingId>,
        content: &str,
    ) -> Result<Note> {
        visible_session(&self.db, user, session_id).await?;
        let content = validate_content(content)?;
        if let Some(finding_id) = finding_id {
            self.ensure_finding_in_session(session_id, finding_id)
                .await?;
        }

        let now = Utc::now();
        let id = sqlx::query(
            "INSERT INTO notes (session_id, finding_id, content, author, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(session_id.to_string())
        .bind(finding_id)
        .bind(&content)
        .bind(&user.username)
        .bind(now)
        .execute(self.db.pool())
        .await
        .map_err(db_err)?
        .last_insert_rowid();

        Ok(Note {
            id,
            session_id,
            finding_id,
            content,
            author: user.username.clone(),
            created_at: now,
            edited_at: None,
        })
    }

    /// Edit a note's content (same emptiness validation as add), stamping the
    /// edited time. Gated on the note's session ownership. An empty/whitespace
    /// edit is rejected and the existing content is left unchanged.
    pub async fn edit_note(&self, user: &User, note_id: i64, content: &str) -> Result<Note> {
        let mut note = self.require_note(note_id).await?;
        visible_session(&self.db, user, note.session_id).await?;
        let content = validate_content(content)?;

        let now = Utc::now();
        sqlx::query("UPDATE notes SET content = ?, edited_at = ? WHERE id = ?")
            .bind(&content)
            .bind(now)
            .bind(note_id)
            .execute(self.db.pool())
            .await
            .map_err(db_err)?;

        note.content = content;
        note.edited_at = Some(now);
        Ok(note)
    }

    /// Delete a note (gated on the note's session ownership). Returns the deleted
    /// note so a caller can re-render the right scope.
    pub async fn delete_note(&self, user: &User, note_id: i64) -> Result<Note> {
        let note = self.require_note(note_id).await?;
        visible_session(&self.db, user, note.session_id).await?;
        sqlx::query("DELETE FROM notes WHERE id = ?")
            .bind(note_id)
            .execute(self.db.pool())
            .await
            .map_err(db_err)?;
        Ok(note)
    }

    /// A session's session-level notes (those not attached to a finding),
    /// newest-first. Gated on session ownership.
    pub async fn session_notes(&self, user: &User, session_id: Uuid) -> Result<Vec<Note>> {
        visible_session(&self.db, user, session_id).await?;
        let rows = sqlx::query(&format!(
            "{NOTE_COLUMNS} WHERE session_id = ? AND finding_id IS NULL \
             ORDER BY created_at DESC, id DESC"
        ))
        .bind(session_id.to_string())
        .fetch_all(self.db.pool())
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_note).collect()
    }

    /// A finding's notes, newest-first. Gated on session ownership; the finding
    /// must belong to the named session.
    pub async fn finding_notes(
        &self,
        user: &User,
        session_id: Uuid,
        finding_id: FindingId,
    ) -> Result<Vec<Note>> {
        visible_session(&self.db, user, session_id).await?;
        self.ensure_finding_in_session(session_id, finding_id)
            .await?;
        let rows = sqlx::query(&format!(
            "{NOTE_COLUMNS} WHERE session_id = ? AND finding_id = ? \
             ORDER BY created_at DESC, id DESC"
        ))
        .bind(session_id.to_string())
        .bind(finding_id)
        .fetch_all(self.db.pool())
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_note).collect()
    }

    // --- Tags -------------------------------------------------------------

    /// Create a tag explicitly: normalize the name (trim + case-fold), reject a
    /// duplicate, and validate the color (`#RRGGBB`, defaulting to
    /// [`DEFAULT_TAG_COLOR`] when none is supplied).
    pub async fn create_tag(
        &self,
        name: &str,
        color: Option<&str>,
        description: Option<&str>,
    ) -> Result<Tag> {
        let name = normalize_tag_name(name)?;
        let color = resolve_color(color)?;
        let description = description
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        // SQLite serializes writers, so the existence check and the insert are
        // race-free against another create (mirrors `auth::register`).
        // ponytail: relies on SQLite's single-writer model; no app-level lock.
        let mut tx = self.db.pool().begin().await.map_err(db_err)?;
        let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tags WHERE name = ?")
            .bind(&name)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
        if existing > 0 {
            // Dropping `tx` rolls back; no row was written.
            return Err(Error::Other(format!("a tag named {name:?} already exists")));
        }
        let id = sqlx::query("INSERT INTO tags (name, color, description) VALUES (?, ?, ?)")
            .bind(&name)
            .bind(&color)
            .bind(&description)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?
            .last_insert_rowid();
        tx.commit().await.map_err(db_err)?;

        Ok(Tag {
            id,
            name,
            color,
            description,
        })
    }

    /// Apply one or more tags to a session, auto-creating any whose normalized
    /// name does not yet exist (with the supplied color, or [`DEFAULT_TAG_COLOR`])
    /// and ignoring any already applied. Gated on session ownership.
    pub async fn apply_tags(&self, user: &User, session_id: Uuid, tags: &[TagApply]) -> Result<()> {
        visible_session(&self.db, user, session_id).await?;
        for tag in tags {
            let name = normalize_tag_name(&tag.name)?;
            let color = resolve_color(tag.color.as_deref())?;

            // Find-or-create. The color is used only when the row is created; an
            // existing tag keeps its own color (OR IGNORE skips the insert).
            sqlx::query(
                "INSERT OR IGNORE INTO tags (name, color, description) VALUES (?, ?, NULL)",
            )
            .bind(&name)
            .bind(&color)
            .execute(self.db.pool())
            .await
            .map_err(db_err)?;
            let tag_id: i64 = sqlx::query_scalar("SELECT id FROM tags WHERE name = ?")
                .bind(&name)
                .fetch_one(self.db.pool())
                .await
                .map_err(db_err)?;

            // Apply, ignoring a re-application (the (session, tag) primary key
            // dedups so a tag is carried at most once).
            sqlx::query("INSERT OR IGNORE INTO session_tags (session_id, tag_id) VALUES (?, ?)")
                .bind(session_id.to_string())
                .bind(tag_id)
                .execute(self.db.pool())
                .await
                .map_err(db_err)?;
        }
        Ok(())
    }

    /// Remove a tag from a session (the tag definition itself remains). Gated on
    /// session ownership. Removing a tag the session does not carry is a no-op.
    pub async fn remove_tag(&self, user: &User, session_id: Uuid, tag_id: i64) -> Result<()> {
        visible_session(&self.db, user, session_id).await?;
        sqlx::query("DELETE FROM session_tags WHERE session_id = ? AND tag_id = ?")
            .bind(session_id.to_string())
            .bind(tag_id)
            .execute(self.db.pool())
            .await
            .map_err(db_err)?;
        Ok(())
    }

    /// List every tag with the number of sessions it is applied to, by name.
    pub async fn list_tags(&self) -> Result<Vec<TagUsage>> {
        let rows = sqlx::query(
            "SELECT t.id, t.name, t.color, t.description, \
                    COUNT(st.session_id) AS session_count \
             FROM tags t LEFT JOIN session_tags st ON st.tag_id = t.id \
             GROUP BY t.id ORDER BY t.name ASC",
        )
        .fetch_all(self.db.pool())
        .await
        .map_err(db_err)?;
        rows.iter()
            .map(|row| {
                Ok(TagUsage {
                    tag: row_to_tag(row)?,
                    session_count: row.try_get("session_count").map_err(db_err)?,
                })
            })
            .collect()
    }

    /// The tags applied to a given session, by name. Gated on session ownership.
    pub async fn session_tags(&self, user: &User, session_id: Uuid) -> Result<Vec<Tag>> {
        visible_session(&self.db, user, session_id).await?;
        let rows = sqlx::query(
            "SELECT t.id, t.name, t.color, t.description \
             FROM tags t JOIN session_tags st ON st.tag_id = t.id \
             WHERE st.session_id = ? ORDER BY t.name ASC",
        )
        .bind(session_id.to_string())
        .fetch_all(self.db.pool())
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_tag).collect()
    }

    // --- Search / filter --------------------------------------------------

    /// Find the sessions whose notes contain `term` (substring match), scoped to
    /// the requester's own sessions — an `admin` searches across all owners.
    pub async fn search_sessions_by_note(
        &self,
        user: &User,
        term: &str,
    ) -> Result<Vec<ScanSession>> {
        let pattern = format!("%{}%", escape_like(term));
        let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(format!(
            "SELECT DISTINCT {SESSION_PROJECTION} \
             FROM sessions s JOIN notes n ON n.session_id = s.session_id \
             WHERE n.content LIKE "
        ));
        qb.push_bind(pattern).push(" ESCAPE '\\'");
        if let Some(owner) = owner_filter(user) {
            qb.push(" AND s.owner_user_id = ").push_bind(owner);
        }
        qb.push(" ORDER BY s.created_at DESC, s.id DESC LIMIT ")
            .push_bind(DEFAULT_SEARCH_LIMIT);

        let rows = qb.build().fetch_all(self.db.pool()).await.map_err(db_err)?;
        rows.iter().map(row_to_session).collect()
    }

    /// Filter sessions by tag name, requiring either all of the named tags
    /// (`match_all`) or any of them. Scoped to the requester's own sessions; an
    /// `admin` filters across all owners.
    pub async fn filter_sessions_by_tags(
        &self,
        user: &User,
        tag_names: &[String],
        match_all: bool,
    ) -> Result<Vec<ScanSession>> {
        // Normalize + dedup the requested names.
        let mut names: Vec<String> = Vec::new();
        for raw in tag_names {
            if let Ok(name) = normalize_tag_name(raw) {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        if names.is_empty() {
            return Ok(Vec::new());
        }

        let ids = self.tag_ids_for_names(&names).await?;
        // A match-all over a name that does not exist can never be satisfied (no
        // session carries it); a match-any over no existing tag matches nothing.
        if ids.is_empty() || (match_all && ids.len() < names.len()) {
            return Ok(Vec::new());
        }

        let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(format!(
            "SELECT {SESSION_PROJECTION} \
             FROM sessions s JOIN session_tags st ON st.session_id = s.session_id \
             WHERE st.tag_id IN ("
        ));
        {
            let mut sep = qb.separated(", ");
            for id in &ids {
                sep.push_bind(*id);
            }
        }
        qb.push(")");
        if let Some(owner) = owner_filter(user) {
            qb.push(" AND s.owner_user_id = ").push_bind(owner);
        }
        qb.push(" GROUP BY s.session_id");
        if match_all {
            qb.push(" HAVING COUNT(DISTINCT st.tag_id) = ")
                .push_bind(ids.len() as i64);
        }
        qb.push(" ORDER BY s.created_at DESC, s.id DESC LIMIT ")
            .push_bind(DEFAULT_SEARCH_LIMIT);

        let rows = qb.build().fetch_all(self.db.pool()).await.map_err(db_err)?;
        rows.iter().map(row_to_session).collect()
    }

    // --- Internals --------------------------------------------------------

    /// Load a note by id, or report it as not found.
    async fn require_note(&self, note_id: i64) -> Result<Note> {
        let row = sqlx::query(&format!("{NOTE_COLUMNS} WHERE id = ?"))
            .bind(note_id)
            .fetch_optional(self.db.pool())
            .await
            .map_err(db_err)?;
        match row {
            Some(row) => row_to_note(&row),
            None => Err(Error::Other(format!("note {note_id} not found"))),
        }
    }

    /// Reject a finding id that does not belong to the named session.
    async fn ensure_finding_in_session(
        &self,
        session_id: Uuid,
        finding_id: FindingId,
    ) -> Result<()> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM findings WHERE id = ? AND session_id = ?")
                .bind(finding_id)
                .bind(session_id.to_string())
                .fetch_one(self.db.pool())
                .await
                .map_err(db_err)?;
        if count == 0 {
            return Err(Error::Other(format!(
                "finding {finding_id} does not belong to this session"
            )));
        }
        Ok(())
    }

    /// Resolve a set of normalized tag names to their existing ids (missing names
    /// are simply absent from the result).
    async fn tag_ids_for_names(&self, names: &[String]) -> Result<Vec<i64>> {
        let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new("SELECT id FROM tags WHERE name IN (");
        {
            let mut sep = qb.separated(", ");
            for name in names {
                sep.push_bind(name.clone());
            }
        }
        qb.push(")");
        let rows = qb.build().fetch_all(self.db.pool()).await.map_err(db_err)?;
        rows.iter()
            .map(|row| row.try_get::<i64, _>("id").map_err(db_err))
            .collect()
    }
}

/// The note column projection, in [`Note`] field order.
const NOTE_COLUMNS: &str =
    "SELECT id, session_id, finding_id, content, author, created_at, edited_at FROM notes";

/// The session columns a note/tag search returns, aliased to `s.*` and including
/// `created_at`/`id` so the `DISTINCT`/`GROUP BY` ordering can reference them.
/// [`row_to_session`] reads only the leading columns by name; the trailing two
/// are present for ordering and ignored on mapping.
const SESSION_PROJECTION: &str = "s.session_id, s.status, s.targets_json, s.scanners_json, \
     s.error_count, s.completed_units, s.total_units, s.started_at, s.finished_at, \
     s.owner_user_id, s.created_at, s.id";

/// `None` for an admin (sees all owners), `Some(id)` to scope to the user's own
/// sessions.
fn owner_filter(user: &User) -> Option<i64> {
    if user.is_admin() {
        None
    } else {
        Some(user.id)
    }
}

/// Trim note content and reject empty/whitespace-only input.
fn validate_content(content: &str) -> Result<String> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(Error::Other("note content must not be empty".to_string()));
    }
    Ok(trimmed.to_string())
}

/// Normalize a tag name (trim + lower-case) and reject an empty one. The
/// normalized form is what is stored and compared, so `Auth-Bypass` and
/// `  auth-bypass ` collapse to the same tag.
fn normalize_tag_name(name: &str) -> Result<String> {
    let normalized = name.trim().to_lowercase();
    if normalized.is_empty() {
        return Err(Error::Other("tag name must not be empty".to_string()));
    }
    Ok(normalized)
}

/// Resolve a tag color: a supplied value must be a valid `#RRGGBB` hex string;
/// absent, it defaults to [`DEFAULT_TAG_COLOR`].
fn resolve_color(color: Option<&str>) -> Result<String> {
    match color.map(str::trim).filter(|s| !s.is_empty()) {
        Some(color) if is_valid_hex_color(color) => Ok(color.to_string()),
        Some(color) => Err(Error::Other(format!(
            "invalid hex color {color:?} (expected #RRGGBB)"
        ))),
        None => Ok(DEFAULT_TAG_COLOR.to_string()),
    }
}

/// Whether `value` is a 7-character `#RRGGBB` hex color.
fn is_valid_hex_color(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(u8::is_ascii_hexdigit)
}

/// Map a `notes` row into a [`Note`].
fn row_to_note(row: &SqliteRow) -> Result<Note> {
    let session_id: String = row.try_get("session_id").map_err(db_err)?;
    Ok(Note {
        id: row.try_get("id").map_err(db_err)?,
        session_id: Uuid::parse_str(&session_id).map_err(db_err)?,
        finding_id: row.try_get("finding_id").map_err(db_err)?,
        content: row.try_get("content").map_err(db_err)?,
        author: row.try_get("author").map_err(db_err)?,
        created_at: row.try_get("created_at").map_err(db_err)?,
        edited_at: row.try_get("edited_at").map_err(db_err)?,
    })
}

/// Map a `tags` row into a [`Tag`].
fn row_to_tag(row: &SqliteRow) -> Result<Tag> {
    Ok(Tag {
        id: row.try_get("id").map_err(db_err)?,
        name: row.try_get("name").map_err(db_err)?,
        color: row.try_get("color").map_err(db_err)?,
        description: row.try_get("description").map_err(db_err)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_or_whitespace_content_is_rejected_and_valid_is_trimmed() {
        assert!(validate_content("").is_err());
        assert!(validate_content("   \t\n ").is_err());
        // Valid content is trimmed of surrounding whitespace.
        assert_eq!(validate_content("  hello  ").unwrap(), "hello");
    }

    #[test]
    fn tag_name_normalization_collapses_case_and_whitespace() {
        assert_eq!(normalize_tag_name("  Auth-Bypass ").unwrap(), "auth-bypass");
        assert_eq!(normalize_tag_name("IDOR").unwrap(), "idor");
        // The two spellings normalize to the same stored name.
        assert_eq!(
            normalize_tag_name("Auth-Bypass").unwrap(),
            normalize_tag_name("auth-bypass").unwrap()
        );
        assert!(normalize_tag_name("   ").is_err());
        assert!(normalize_tag_name("").is_err());
    }

    #[test]
    fn hex_color_validation_accepts_rrggbb_and_rejects_the_rest() {
        assert!(is_valid_hex_color("#6B7280"));
        assert!(is_valid_hex_color("#000000"));
        assert!(is_valid_hex_color("#ffffff"));
        // Wrong length, missing hash, non-hex, shorthand — all rejected.
        assert!(!is_valid_hex_color("6B7280"));
        assert!(!is_valid_hex_color("#6B728"));
        assert!(!is_valid_hex_color("#6B72800"));
        assert!(!is_valid_hex_color("#GGGGGG"));
        assert!(!is_valid_hex_color("#fff"));
        assert!(!is_valid_hex_color(""));
    }

    #[test]
    fn resolve_color_defaults_when_absent_and_validates_when_present() {
        assert_eq!(resolve_color(None).unwrap(), DEFAULT_TAG_COLOR);
        assert_eq!(resolve_color(Some("   ")).unwrap(), DEFAULT_TAG_COLOR);
        assert_eq!(resolve_color(Some("#abcdef")).unwrap(), "#abcdef");
        assert!(resolve_color(Some("not-a-color")).is_err());
    }
}
