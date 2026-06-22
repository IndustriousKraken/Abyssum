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
use sqlx::Row;

use crate::error::{Error, Result};

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

    /// Seed the store from the bundled assets, **idempotently**.
    ///
    /// Keyed by natural identity (list name + value for wordlist entries; value
    /// for User-Agents), so it always tops up only the missing rows — there is no
    /// content-hash check or version stamp. Running it against a fully populated
    /// store is a no-op; running it against a partially populated one inserts
    /// exactly what is absent. Re-seeding never creates duplicates.
    pub async fn seed(&self) -> Result<()> {
        self.seed_wordlists().await?;
        self.seed_user_agents().await?;
        Ok(())
    }

    /// Seed every bundled wordlist and its entries in one transaction.
    async fn seed_wordlists(&self) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        for asset in assets::WORDLISTS {
            // The list row must exist before its entries (FK), and `OR IGNORE`
            // keeps re-seeding a no-op.
            sqlx::query("INSERT OR IGNORE INTO wordlists (name) VALUES (?)")
                .bind(asset.name)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;

            for (position, entry) in assets::parse_wordlist(asset).into_iter().enumerate() {
                sqlx::query(
                    "INSERT OR IGNORE INTO wordlist_entries (list_name, value, label, position) \
                     VALUES (?, ?, ?, ?)",
                )
                .bind(asset.name)
                .bind(entry.value)
                .bind(entry.label)
                .bind(position as i64)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            }
        }
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    /// Seed the User-Agent pool in one transaction, keyed by value.
    async fn seed_user_agents(&self) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        for ua in assets::parse_user_agents() {
            sqlx::query(
                "INSERT OR IGNORE INTO user_agents (value, category, realistic) VALUES (?, ?, ?)",
            )
            .bind(ua.value)
            .bind(ua.category)
            .bind(ua.realistic)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        }
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

/// Wrap any displayable error (sqlx, …) as [`Error::Database`].
fn db_err<E: std::fmt::Display>(err: E) -> Error {
    Error::Database(err.to_string())
}
