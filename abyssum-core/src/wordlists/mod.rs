//! Per-user custom wordlists — operator-provided lists imported through the UI.
//!
//! The seeded reference lists ([`ReferenceStore`](crate::seed::ReferenceStore))
//! are curated, read-only, and shared by everyone. A **custom wordlist** is the
//! operator's own list of terms — pasted or uploaded as a `.txt` file in the web
//! UI — owned by and private to that user, and selectable per scan. It is stored
//! in its own tables (`user_wordlists` / `user_wordlist_entries`), distinct from
//! the seeded ones, so re-seeding the built-ins never touches a user's lists.
//!
//! On import the raw text is **normalized** — trimmed, blank/comment lines
//! dropped, lowercased, and de-duplicated — and the result is **reported**
//! ([`ImportReport`]) rather than imported silently, so an operator sees how many
//! entries were kept and how many were dropped and why.
//!
//! [`CustomWordlistStore`] is the per-user authority: it enforces ownership on
//! every read and write, mirroring [`TimingProfileStore`](crate::timing::TimingProfileStore).
//! Scanners never touch it — they read the *selected* list back through the shared
//! [`ReferenceStore::wordlist_values_for`](crate::seed::ReferenceStore::wordlist_values_for)
//! lookup, keyed by the id a surface validated as owned by the scan's operator.

use crate::error::{Error, Result, db_err};
use crate::persistence::DatabaseManager;

/// Maximum length of a custom wordlist's name (characters, after trimming).
const MAX_NAME_CHARS: usize = 80;

/// A user's custom wordlist: its id, owner, name, and entry count. The entries
/// themselves are read separately (by the scanner, through the reference store).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomWordlist {
    /// Stable per-row id (owner-scoped when addressed).
    pub id: i64,
    /// The owning user's id. A list is only ever visible/selectable by its owner.
    pub owner_user_id: i64,
    /// Human-facing name, unique within the owner's set.
    pub name: String,
    /// How many normalized entries the list holds.
    pub entry_count: i64,
}

/// The outcome of an import: how many entries were kept, and how many were dropped
/// broken down by reason. Reported to the operator rather than importing silently.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Entries kept after normalization (trimmed, non-blank, non-comment, unique).
    pub imported: usize,
    /// Lines dropped because they were blank after trimming.
    pub dropped_blank: usize,
    /// Lines dropped because they were comments (started with `#`).
    pub dropped_comment: usize,
    /// Lines dropped because they duplicated an entry already kept.
    pub dropped_duplicate: usize,
}

impl ImportReport {
    /// Total lines dropped for any reason.
    pub fn dropped(&self) -> usize {
        self.dropped_blank + self.dropped_comment + self.dropped_duplicate
    }
}

/// Normalize raw import text into a wordlist, reporting what was dropped.
///
/// Each line is trimmed; a line that is empty afterward is dropped as *blank*, one
/// beginning with `#` is dropped as a *comment*, otherwise it is lowercased and,
/// unless it duplicates an already-kept entry, retained. Order is preserved (first
/// occurrence wins) so a later lookup and any truncation are deterministic. Pure,
/// so it is unit-testable without a database. No DNS-label / apex validation
/// happens here — a custom list can feed any consumer, and the subdomain scanner
/// still runs every entry through its own label validation and apex confinement.
pub fn normalize(raw: &str) -> (Vec<String>, ImportReport) {
    let mut report = ImportReport::default();
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            report.dropped_blank += 1;
            continue;
        }
        if trimmed.starts_with('#') {
            report.dropped_comment += 1;
            continue;
        }
        let value = trimmed.to_lowercase();
        if seen.insert(value.clone()) {
            out.push(value);
        } else {
            report.dropped_duplicate += 1;
        }
    }
    report.imported = out.len();
    (out, report)
}

/// The per-user custom-wordlist authority over the shared store. Cheap to clone
/// (the inner [`DatabaseManager`] is a reference-counted pool).
#[derive(Debug, Clone)]
pub struct CustomWordlistStore {
    db: DatabaseManager,
}

impl CustomWordlistStore {
    /// Build over a [`DatabaseManager`] (already migrated after
    /// [`DatabaseManager::connect`]).
    pub fn from_database(db: &DatabaseManager) -> Self {
        Self { db: db.clone() }
    }

    /// Import `raw` text as a wordlist named `name`, owned by `user_id`. The name
    /// is trimmed and must be non-empty, bounded in length, and unique within the
    /// owner's set. The text is normalized (see [`normalize`]); an import that
    /// yields no entries is rejected so an empty list is never stored. Returns the
    /// created list together with the [`ImportReport`].
    pub async fn import(
        &self,
        user_id: i64,
        name: &str,
        raw: &str,
    ) -> Result<(CustomWordlist, ImportReport)> {
        let name = validate_name(name)?;
        let (entries, report) = normalize(raw);
        if entries.is_empty() {
            return Err(Error::Other(
                "no wordlist entries after normalization (all lines were blank, comments, or duplicates)"
                    .to_string(),
            ));
        }

        let existing: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM user_wordlists WHERE owner_user_id = ? AND name = ?",
        )
        .bind(user_id)
        .bind(&name)
        .fetch_one(self.db.pool())
        .await
        .map_err(db_err)?;
        if existing > 0 {
            return Err(Error::Other(format!(
                "a wordlist named {name:?} already exists"
            )));
        }

        let mut tx = self.db.pool().begin().await.map_err(db_err)?;
        let id = sqlx::query("INSERT INTO user_wordlists (owner_user_id, name) VALUES (?, ?)")
            .bind(user_id)
            .bind(&name)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?
            .last_insert_rowid();
        for (position, value) in entries.iter().enumerate() {
            sqlx::query(
                "INSERT INTO user_wordlist_entries (wordlist_id, value, position) VALUES (?, ?, ?)",
            )
            .bind(id)
            .bind(value)
            .bind(position as i64)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)?;

        Ok((
            CustomWordlist {
                id,
                owner_user_id: user_id,
                name,
                entry_count: entries.len() as i64,
            },
            report,
        ))
    }

    /// Every custom wordlist owned by `user_id`, most-recently-created first, each
    /// carrying its entry count. Only the owner's lists are returned.
    pub async fn list_for_user(&self, user_id: i64) -> Result<Vec<CustomWordlist>> {
        let rows = sqlx::query(
            "SELECT w.id, w.owner_user_id, w.name, \
                    (SELECT COUNT(*) FROM user_wordlist_entries e WHERE e.wordlist_id = w.id) \
                      AS entry_count \
             FROM user_wordlists w WHERE w.owner_user_id = ? ORDER BY w.id DESC",
        )
        .bind(user_id)
        .fetch_all(self.db.pool())
        .await
        .map_err(db_err)?;
        rows.iter().map(row_to_wordlist).collect()
    }

    /// One custom wordlist by id, **owner-scoped**: a row owned by another user (or
    /// an absent id) yields `None`, never the row. This is the ownership gate a
    /// surface calls before recording the selection on a scan, so a crafted id can
    /// never select another user's list.
    pub async fn get_for_user(&self, user_id: i64, id: i64) -> Result<Option<CustomWordlist>> {
        let row = sqlx::query(
            "SELECT w.id, w.owner_user_id, w.name, \
                    (SELECT COUNT(*) FROM user_wordlist_entries e WHERE e.wordlist_id = w.id) \
                      AS entry_count \
             FROM user_wordlists w WHERE w.id = ? AND w.owner_user_id = ?",
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(self.db.pool())
        .await
        .map_err(db_err)?;
        row.as_ref().map(row_to_wordlist).transpose()
    }
}

/// Trim + validate a wordlist name: non-empty after trimming, bounded length.
fn validate_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(Error::Other("wordlist name is required".to_string()));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(Error::Other(format!(
            "wordlist name is too long (max {MAX_NAME_CHARS} characters)"
        )));
    }
    Ok(name.to_string())
}

/// Map a `user_wordlists` row (with a computed `entry_count`) into a [`CustomWordlist`].
fn row_to_wordlist(row: &sqlx::sqlite::SqliteRow) -> Result<CustomWordlist> {
    use sqlx::Row;
    Ok(CustomWordlist {
        id: row.try_get("id").map_err(db_err)?,
        owner_user_id: row.try_get("owner_user_id").map_err(db_err)?,
        name: row.try_get("name").map_err(db_err)?,
        entry_count: row.try_get("entry_count").map_err(db_err)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_trims_drops_blanks_comments_and_dedupes_case_insensitively() {
        let raw = "\
API\n\
  api  \n\
\n\
# a comment\n\
   \n\
Mail\n\
mail\n\
www";
        let (entries, report) = normalize(raw);
        // Trimmed + lowercased + first-occurrence-wins dedup, order preserved.
        assert_eq!(entries, vec!["api", "mail", "www"]);
        assert_eq!(report.imported, 3);
        assert_eq!(report.dropped_blank, 2); // the empty line and the whitespace line
        assert_eq!(report.dropped_comment, 1);
        assert_eq!(report.dropped_duplicate, 2); // "api" again, "mail" again
        assert_eq!(report.dropped(), 5);
    }

    #[test]
    fn normalize_empty_input_yields_nothing() {
        let (entries, report) = normalize("\n\n   \n# only comments\n");
        assert!(entries.is_empty());
        assert_eq!(report.imported, 0);
        assert!(report.dropped() > 0);
    }

    #[test]
    fn name_validation_trims_and_bounds() {
        assert_eq!(validate_name("  My List  ").unwrap(), "My List");
        assert!(validate_name("   ").is_err());
        assert!(validate_name(&"x".repeat(MAX_NAME_CHARS + 1)).is_err());
    }
}
