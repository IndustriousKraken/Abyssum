//! The reference-data store: seeds and serves the curated wordlists and the
//! User-Agent pool over the shared persistence pool.
//!
//! [`ReferenceStore`] is the **single source** scanners read their candidate
//! paths and queries from (see the change's design): probing and any future
//! inspection UI share one store rather than the scanners carrying compiled-in
//! constants. It is cheaply cloneable (the pool is `Arc`-backed) and is built
//! over the same [`SqlitePool`] that [`DatabaseManager`] owns, so the seed tables
//! live alongside sessions and findings.
//!
//! [`DatabaseManager`]: crate::persistence::DatabaseManager

use sqlx::sqlite::SqlitePool;
use sqlx::{Row, Sqlite, Transaction};

use crate::error::{db_err, Result};

use super::assets;

/// A wordlist entry returned from a lookup: its value, plus an optional label
/// (e.g. a named GraphQL query's name). Plain lists carry `None` labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WordlistEntry {
    /// The candidate path / query body.
    pub value: String,
    /// The entry's label, if the list is labeled; `None` for plain lists.
    pub label: Option<String>,
}

/// A User-Agent from the seeded pool: the header value, its category, and whether
/// it is realistic (eligible for the default stealth rotation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PooledUserAgent {
    /// The literal `User-Agent` header value.
    pub value: String,
    /// Coarse category (browser, mobile, bot, security), if stored.
    pub category: Option<String>,
    /// Whether this identity is part of the default rotation pool.
    pub realistic: bool,
}

/// Seeds and serves curated reference data over a shared SQLite pool.
#[derive(Debug, Clone)]
pub struct ReferenceStore {
    pool: SqlitePool,
}

impl ReferenceStore {
    /// Build a store over an existing pool (typically `DatabaseManager::pool`).
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Seed the store from the bundled assets, **idempotently** and **atomically**.
    ///
    /// Keyed by natural identity (list name + value for wordlist entries; value
    /// for User-Agents), so re-seeding never creates duplicates — there is no
    /// content-hash check or version stamp. On a conflict the row's non-identity
    /// metadata (a wordlist entry's `label`/`position`; a User-Agent's
    /// `category`/`realistic`) is refreshed to the current bundled value via
    /// `ON CONFLICT DO UPDATE`, so a later asset revision that moves or relabels an
    /// existing entry is reflected on the next seed rather than leaving the old row
    /// stale. Running it against a fully populated, unchanged store still touches
    /// no row counts.
    ///
    /// The wordlists and the User-Agent pool are seeded inside a **single**
    /// transaction, so a failure partway through rolls the whole seed back rather
    /// than leaving the store half-populated. (Seeding is idempotent, so the next
    /// `connect` would also recover — but one transaction avoids the intermediate
    /// state entirely.)
    pub async fn seed(&self) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        seed_wordlists(&mut tx).await?;
        seed_user_agents(&mut tx).await?;
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    /// Return a named wordlist's entries (value + optional label) in seeded order.
    ///
    /// A list name that is **not present** yields an empty vec rather than an
    /// error — a scanner asking for a list nobody seeded simply gets no
    /// candidates, never an abnormal failure.
    pub async fn wordlist(&self, name: &str) -> Result<Vec<WordlistEntry>> {
        let rows = sqlx::query(
            "SELECT value, label FROM wordlist_entries WHERE list_name = ? \
             ORDER BY position ASC, id ASC",
        )
        .bind(name)
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        rows.iter()
            .map(|row| {
                Ok(WordlistEntry {
                    value: row.try_get("value").map_err(db_err)?,
                    label: row.try_get("label").map_err(db_err)?,
                })
            })
            .collect()
    }

    /// Return just the values of a named wordlist, in seeded order — a
    /// convenience for plain (label-less) lists. Absent lists yield an empty vec.
    pub async fn wordlist_values(&self, name: &str) -> Result<Vec<String>> {
        Ok(self
            .wordlist(name)
            .await?
            .into_iter()
            .map(|entry| entry.value)
            .collect())
    }

    /// The full seeded User-Agent pool, each entry marked realistic or not, in
    /// seeded order.
    pub async fn user_agents(&self) -> Result<Vec<PooledUserAgent>> {
        let rows =
            sqlx::query("SELECT value, category, realistic FROM user_agents ORDER BY id ASC")
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;

        rows.iter()
            .map(|row| {
                Ok(PooledUserAgent {
                    value: row.try_get("value").map_err(db_err)?,
                    category: row.try_get("category").map_err(db_err)?,
                    realistic: row.try_get("realistic").map_err(db_err)?,
                })
            })
            .collect()
    }

    /// The realistic subset's header values, in seeded order — the default
    /// rotation pool. Scanner-announcing identities are excluded.
    pub async fn realistic_user_agents(&self) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT value FROM user_agents WHERE realistic = 1 ORDER BY id ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(db_err)?;

        rows.iter()
            .map(|row| row.try_get("value").map_err(db_err))
            .collect()
    }
}

/// Seed every bundled wordlist and its entries within the caller's transaction
/// (see [`ReferenceStore::seed`]).
///
/// The list row is created first so the entries' foreign key resolves. Each entry
/// upserts on its `(list_name, value)` identity: a new entry is inserted, while an
/// existing one has its `label`/`position` refreshed to the current bundled value
/// so a later asset revision is not left stale.
async fn seed_wordlists(tx: &mut Transaction<'_, Sqlite>) -> Result<()> {
    for asset in assets::WORDLISTS {
        // The list row only carries its name (its identity), so there is nothing
        // to refresh on conflict — `OR IGNORE` keeps re-seeding a no-op.
        sqlx::query("INSERT OR IGNORE INTO wordlists (name) VALUES (?)")
            .bind(asset.name)
            .execute(&mut **tx)
            .await
            .map_err(db_err)?;

        for (position, entry) in assets::parse_wordlist(asset).into_iter().enumerate() {
            sqlx::query(
                "INSERT INTO wordlist_entries (list_name, value, label, position) \
                 VALUES (?, ?, ?, ?) \
                 ON CONFLICT(list_name, value) DO UPDATE SET \
                   label    = excluded.label, \
                   position = excluded.position",
            )
            .bind(asset.name)
            .bind(entry.value)
            .bind(entry.label)
            .bind(position as i64)
            .execute(&mut **tx)
            .await
            .map_err(db_err)?;
        }
    }
    Ok(())
}

/// Seed the User-Agent pool within the caller's transaction, keyed by value (see
/// [`ReferenceStore::seed`]).
///
/// Each User-Agent upserts on its `value` identity: a new one is inserted, while
/// an existing one has its `category`/`realistic` classification refreshed to the
/// current bundled value. Keeping `realistic` current matters for stealth — a UA
/// re-classified out of the realistic pool in a later asset revision must actually
/// leave the default rotation rather than linger on a stale flag.
async fn seed_user_agents(tx: &mut Transaction<'_, Sqlite>) -> Result<()> {
    for ua in assets::parse_user_agents() {
        sqlx::query(
            "INSERT INTO user_agents (value, category, realistic) VALUES (?, ?, ?) \
             ON CONFLICT(value) DO UPDATE SET \
               category  = excluded.category, \
               realistic = excluded.realistic",
        )
        .bind(ua.value)
        .bind(ua.category)
        .bind(ua.realistic)
        .execute(&mut **tx)
        .await
        .map_err(db_err)?;
    }
    Ok(())
}
