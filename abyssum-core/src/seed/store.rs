//! The [`SeedStore`]: reads and writes the curated reference-data tables.
//!
//! It shares the persistence connection pool (the tables are added by this
//! capability's migration, which runs alongside the persistence migrations) and
//! provides the two operations the rest of the system needs:
//!
//! - [`seed`](SeedStore::seed) — copy the bundled assets into the store. Idempotent
//!   and keyed by natural identity, so first-run self-seeding and an explicit
//!   installer/CLI invocation share one code path and a re-run only tops up gaps.
//! - [`wordlist`](SeedStore::wordlist) / [`user_agents`](SeedStore::user_agents) —
//!   the named lookups scanners and the rotating User-Agent source read from. A
//!   lookup for an absent list returns no candidates rather than failing.

use sqlx::{Row, SqlitePool};

use crate::error::Result;
use crate::persistence::DatabaseManager;

use super::assets::{self, WordlistEntry};

/// A seeded User-Agent as read back from the store: the header `value`, its coarse
/// `category`, and whether it belongs to the realistic (default rotation) subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserAgentRecord {
    /// The literal `User-Agent` header value.
    pub value: String,
    /// Coarse category, e.g. `browser`, `mobile`, `bot`, `security`.
    pub category: Option<String>,
    /// Whether the entry is part of the default (realistic) rotation pool.
    pub realistic: bool,
}

/// What a [`seed`](SeedStore::seed) run inserted: rows actually added this run,
/// per table. Zero across the board means the store was already fully populated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeedSummary {
    /// New `wordlists` rows (named lists first seen this run).
    pub lists_added: u64,
    /// New `wordlist_entries` rows.
    pub entries_added: u64,
    /// New `user_agents` rows.
    pub user_agents_added: u64,
}

impl SeedSummary {
    /// Whether this run inserted nothing — i.e. the store was already current.
    pub fn is_noop(&self) -> bool {
        self.lists_added == 0 && self.entries_added == 0 && self.user_agents_added == 0
    }
}

/// Reads and seeds the curated reference-data tables over the shared pool.
#[derive(Debug, Clone)]
pub struct SeedStore {
    pool: SqlitePool,
}

impl SeedStore {
    /// Build a store over a connection pool (the tables already exist — their
    /// migration ran when the pool was opened).
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Build a store sharing a [`DatabaseManager`]'s pool. The usual entry point:
    /// open the database, then `SeedStore::from_manager(&db)`.
    pub fn from_manager(db: &DatabaseManager) -> Self {
        Self::new(db.pool().clone())
    }

    /// Seed the store from the bundled assets, inserting only rows that are
    /// missing. This is **the** seed entry point — first-run self-seeding and an
    /// explicit installer/CLI invocation both call it.
    ///
    /// Idempotent by natural identity: wordlist entries key on `(list_name, value)`
    /// and User-Agents on `value`, so a re-run against a populated store inserts
    /// nothing and a run against a partially populated one inserts exactly the
    /// gaps. Each entry's `position` comes from its bundled order, so a top-up
    /// still lands it where it belongs regardless of insertion order. Runs in one
    /// transaction so the store is never observed half-seeded.
    pub async fn seed(&self) -> Result<SeedSummary> {
        let mut summary = SeedSummary::default();
        let mut tx = self.pool.begin().await?;

        for name in assets::wordlist_names() {
            let list_rows = sqlx::query("INSERT OR IGNORE INTO wordlists (name) VALUES (?)")
                .bind(name)
                .execute(&mut *tx)
                .await?;
            summary.lists_added += list_rows.rows_affected();

            for (position, entry) in assets::bundled_wordlist(name).into_iter().enumerate() {
                let result = sqlx::query(
                    "INSERT OR IGNORE INTO wordlist_entries (list_name, value, label, position) \
                     VALUES (?, ?, ?, ?)",
                )
                .bind(name)
                .bind(entry.value)
                .bind(entry.label)
                .bind(position as i64)
                .execute(&mut *tx)
                .await?;
                summary.entries_added += result.rows_affected();
            }
        }

        for agent in assets::bundled_user_agents()? {
            let result = sqlx::query(
                "INSERT OR IGNORE INTO user_agents (value, category, realistic) VALUES (?, ?, ?)",
            )
            .bind(agent.value)
            .bind(agent.category)
            .bind(agent.realistic)
            .execute(&mut *tx)
            .await?;
            summary.user_agents_added += result.rows_affected();
        }

        tx.commit().await?;
        Ok(summary)
    }

    /// Return the named wordlist's entries in seeded order. A list name that is not
    /// present yields an empty vector — a missing list is no candidates, never a
    /// failure (the single-source contract).
    pub async fn wordlist(&self, name: &str) -> Result<Vec<WordlistEntry>> {
        let rows = sqlx::query(
            "SELECT value, label FROM wordlist_entries \
             WHERE list_name = ? ORDER BY position ASC, id ASC",
        )
        .bind(name)
        .fetch_all(&self.pool)
        .await?;

        let entries = rows
            .iter()
            .map(|row| {
                Ok(WordlistEntry {
                    value: row.try_get("value")?,
                    label: row.try_get("label")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(entries)
    }

    /// Just the `value`s of a named wordlist, in seeded order — the common case for
    /// a scanner that probes paths and has no use for labels.
    pub async fn wordlist_values(&self, name: &str) -> Result<Vec<String>> {
        Ok(self
            .wordlist(name)
            .await?
            .into_iter()
            .map(|entry| entry.value)
            .collect())
    }

    /// The full seeded User-Agent pool, each entry marked realistic or not.
    pub async fn user_agents(&self) -> Result<Vec<UserAgentRecord>> {
        let rows =
            sqlx::query("SELECT value, category, realistic FROM user_agents ORDER BY id ASC")
                .fetch_all(&self.pool)
                .await?;
        rows.iter().map(row_to_user_agent).collect()
    }

    /// The realistic (default rotation) subset of the pool, in seeded order. This
    /// is what [`RotatingUserAgent`](super::RotatingUserAgent) draws from so the
    /// default never presents a scanner-announcing identity.
    pub async fn realistic_user_agents(&self) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT value FROM user_agents WHERE realistic = 1 ORDER BY id ASC")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| Ok(row.try_get::<String, _>("value")?))
            .collect()
    }
}

/// Reconstruct a [`UserAgentRecord`] from a row.
fn row_to_user_agent(row: &sqlx::sqlite::SqliteRow) -> Result<UserAgentRecord> {
    Ok(UserAgentRecord {
        value: row.try_get("value")?,
        category: row.try_get("category")?,
        realistic: row.try_get("realistic")?,
    })
}
