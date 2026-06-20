//! The [`DatabaseManager`]: the single owner of the persistence connection pool.
//!
//! It opens (creating if absent) an embedded SQLite file from the bootstrap
//! `database.path`, applies any pending migrations on startup, and exposes async
//! methods to store and query scan sessions and findings. A pooled connection is
//! created once and cloned cheaply; orchestration and the surfaces call these
//! methods — scanners never touch the store directly.

use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions, SqliteRow};
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};
use uuid::Uuid;

use crate::config::DatabaseConfig;
use crate::error::{Error, Result};
use crate::scan::Finding;

use super::records::{
    self, severity_counts_zeroed, FindingFilter, SessionRecord, SessionWithFindings, StoredFinding,
    StoredSession, SummaryCounts,
};

/// The embedded migration set (the `migrations/` directory), compiled in at build
/// time and applied idempotently against the `_sqlx_migrations` tracking table.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Default cap on a finding search when the caller specifies no limit.
const DEFAULT_SEARCH_LIMIT: i64 = 1000;

/// Owns one SQLite connection pool and serves every persistence operation.
#[derive(Debug, Clone)]
pub struct DatabaseManager {
    pool: SqlitePool,
}

impl DatabaseManager {
    /// Open (creating if absent) the store at the configured `database.path`,
    /// then run pending migrations. Convenience over [`open`](Self::open).
    pub async fn connect(config: &DatabaseConfig) -> Result<Self> {
        Self::open(&config.path).await
    }

    /// Open (creating if absent) the store at `path`, creating its parent
    /// directory if missing, then apply any pending migrations.
    ///
    /// A failure to open the pool surfaces as [`Error::Persistence`]; a failure to
    /// create the parent directory as [`Error::Io`].
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await?;

        let manager = Self { pool };
        manager.run_migrations().await?;
        Ok(manager)
    }

    /// Apply pending migrations. Idempotent: migrations already recorded in
    /// `_sqlx_migrations` are skipped, so re-running against a current store is a
    /// no-op. Runs on startup before any query is served.
    async fn run_migrations(&self) -> Result<()> {
        MIGRATOR.run(&self.pool).await?;
        Ok(())
    }

    /// The underlying pool, for callers that need to share it.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Close the pool, awaiting in-flight connections. Useful before reopening the
    /// same file (e.g. simulating a restart).
    pub async fn close(&self) {
        self.pool.close().await;
    }

    // --- Sessions -------------------------------------------------------------

    /// Create or update a session by its `session_id` (upsert). Re-storing the
    /// same id updates the existing row in place — advancing status, timing, and
    /// counts — rather than inserting a duplicate, and preserves the original
    /// `created_at`.
    pub async fn upsert_session(&self, session: &SessionRecord) -> Result<()> {
        let now = Utc::now();
        let targets_json = to_json(&session.targets)?;
        let scanners_json = to_json(&session.scanner_ids)?;

        sqlx::query(
            "INSERT INTO sessions \
                (session_id, status, targets_json, scanners_json, start_time, end_time, \
                 total_requests, error_count, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(session_id) DO UPDATE SET \
                status = excluded.status, \
                targets_json = excluded.targets_json, \
                scanners_json = excluded.scanners_json, \
                start_time = excluded.start_time, \
                end_time = excluded.end_time, \
                total_requests = excluded.total_requests, \
                error_count = excluded.error_count, \
                updated_at = excluded.updated_at",
        )
        .bind(session.session_id.to_string())
        .bind(records::session_status_to_str(session.status))
        .bind(targets_json)
        .bind(scanners_json)
        .bind(session.start_time)
        .bind(session.end_time)
        .bind(session.total_requests)
        .bind(session.error_count)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Fetch a single session by `session_id`, or `None` if none has that id.
    pub async fn get_session(&self, session_id: Uuid) -> Result<Option<StoredSession>> {
        let row = sqlx::query(SESSION_COLUMNS_SELECT)
            .bind(session_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(row_to_session).transpose()
    }

    /// Fetch a session together with all of its findings, or `None` if no session
    /// has that id.
    pub async fn get_session_with_findings(
        &self,
        session_id: Uuid,
    ) -> Result<Option<SessionWithFindings>> {
        let Some(session) = self.get_session(session_id).await? else {
            return Ok(None);
        };
        let findings = self.findings_for_session(session_id).await?;
        Ok(Some(SessionWithFindings { session, findings }))
    }

    /// List sessions most-recently-created first, paged by `limit`/`offset`.
    pub async fn list_sessions(&self, limit: i64, offset: i64) -> Result<Vec<StoredSession>> {
        let rows = sqlx::query(&format!(
            "{SESSION_COLUMNS_SELECT_ALL} ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_session).collect()
    }

    /// Delete a session and all of its findings in one transaction. Returns
    /// whether a session row was actually removed.
    pub async fn delete_session(&self, session_id: Uuid) -> Result<bool> {
        let id = session_id.to_string();
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM findings WHERE session_id = ?")
            .bind(&id)
            .execute(&mut *tx)
            .await?;

        let result = sqlx::query("DELETE FROM sessions WHERE session_id = ?")
            .bind(&id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(result.rows_affected() > 0)
    }

    // --- Findings -------------------------------------------------------------

    /// Save a finding under `session_id`, assigning it a fresh public
    /// `finding_id` (uuid). Returns the [`StoredFinding`], whose inner
    /// [`Finding::id`] carries the assigned row id.
    pub async fn save_finding(&self, session_id: Uuid, finding: &Finding) -> Result<StoredFinding> {
        let finding_id = Uuid::new_v4();
        let now = Utc::now();
        let target_json = to_json(&finding.target)?;
        let evidence_json = match &finding.evidence {
            Some(value) => Some(to_json(value)?),
            None => None,
        };

        let row = sqlx::query(
            "INSERT INTO findings \
                (finding_id, session_id, scanner_id, status, severity, title, description, \
                 recommendations, target_url, target_full_url, target_json, evidence_json, \
                 timestamp, created_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             RETURNING id",
        )
        .bind(finding_id.to_string())
        .bind(session_id.to_string())
        .bind(finding.scanner_id.as_str())
        .bind(records::status_to_str(finding.status))
        .bind(records::severity_to_str(finding.severity))
        .bind(finding.title.as_str())
        .bind(finding.description.as_deref())
        .bind(finding.recommendations.as_deref())
        .bind(finding.target.base_url().as_str())
        .bind(finding.target.full_url().to_string())
        .bind(target_json)
        .bind(evidence_json)
        .bind(finding.timestamp)
        .bind(now)
        .fetch_one(&self.pool)
        .await?;

        let id: i64 = row.try_get("id")?;
        let mut stored = finding.clone();
        stored.id = Some(id);
        Ok(StoredFinding {
            finding_id,
            finding: stored,
        })
    }

    /// Fetch all findings for a session, oldest-first by timestamp. Each carries
    /// its stable `finding_id`.
    pub async fn findings_for_session(&self, session_id: Uuid) -> Result<Vec<StoredFinding>> {
        let rows = sqlx::query(&format!(
            "{FINDING_COLUMNS_SELECT} WHERE session_id = ? ORDER BY timestamp ASC, id ASC"
        ))
        .bind(session_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_finding).collect()
    }

    /// Search findings by any combination of the supported filters, newest-first.
    ///
    /// Supplied filters combine with AND. A free-text query matches the title or
    /// description case-insensitively; a date range bounds the finding timestamp
    /// inclusively. The result is capped by the filter's `limit`
    /// (default [`DEFAULT_SEARCH_LIMIT`]).
    pub async fn search_findings(&self, filter: &FindingFilter) -> Result<Vec<StoredFinding>> {
        let mut builder: QueryBuilder<Sqlite> =
            QueryBuilder::new(format!("{FINDING_COLUMNS_SELECT} WHERE 1 = 1"));

        if let Some(session_id) = filter.session_id {
            builder
                .push(" AND session_id = ")
                .push_bind(session_id.to_string());
        }
        if let Some(status) = filter.status {
            builder
                .push(" AND status = ")
                .push_bind(records::status_to_str(status));
        }
        if let Some(severity) = filter.severity {
            builder
                .push(" AND severity = ")
                .push_bind(records::severity_to_str(severity));
        }
        if let Some(scanner_id) = &filter.scanner_id {
            builder
                .push(" AND scanner_id = ")
                .push_bind(scanner_id.clone());
        }
        if let Some(target) = &filter.target {
            builder
                .push(" AND target_full_url = ")
                .push_bind(target.clone());
        }
        if let Some(query) = &filter.query {
            let pattern = format!("%{}%", escape_like(query));
            builder
                .push(" AND (title LIKE ")
                .push_bind(pattern.clone())
                .push(" ESCAPE '\\' OR description LIKE ")
                .push_bind(pattern)
                .push(" ESCAPE '\\')");
        }
        if let Some(from) = filter.from {
            builder.push(" AND timestamp >= ").push_bind(from);
        }
        if let Some(to) = filter.to {
            builder.push(" AND timestamp <= ").push_bind(to);
        }

        builder.push(" ORDER BY timestamp DESC, id DESC LIMIT ");
        builder.push_bind(filter.limit.unwrap_or(DEFAULT_SEARCH_LIMIT));

        let rows = builder.build().fetch_all(&self.pool).await?;
        rows.iter().map(row_to_finding).collect()
    }

    /// Summary counts over stored data: total sessions, total findings, and a
    /// per-severity breakdown. When `session_ids` is `Some`, counts are restricted
    /// to that subset of sessions (an empty subset yields all-zero counts); when
    /// `None`, the whole store is counted.
    pub async fn summary_counts(&self, session_ids: Option<&[Uuid]>) -> Result<SummaryCounts> {
        let ids: Option<Vec<String>> =
            session_ids.map(|ids| ids.iter().map(Uuid::to_string).collect());

        if let Some(ids) = &ids {
            if ids.is_empty() {
                return Ok(SummaryCounts::zeroed());
            }
        }

        let sessions = self.count_scalar("sessions", ids.as_deref()).await?;
        let findings = self.count_scalar("findings", ids.as_deref()).await?;
        let by_severity = self.count_by_severity(ids.as_deref()).await?;

        Ok(SummaryCounts {
            sessions,
            findings,
            by_severity,
        })
    }

    /// `COUNT(*)` over `table`, optionally restricted to a subset of session ids.
    async fn count_scalar(&self, table: &str, ids: Option<&[String]>) -> Result<i64> {
        let mut builder: QueryBuilder<Sqlite> =
            QueryBuilder::new(format!("SELECT COUNT(*) FROM {table}"));
        if let Some(ids) = ids {
            builder.push(" WHERE session_id IN (");
            let mut separated = builder.separated(", ");
            for id in ids {
                separated.push_bind(id);
            }
            separated.push_unseparated(")");
        }
        let count: i64 = builder.build_query_scalar().fetch_one(&self.pool).await?;
        Ok(count)
    }

    /// Findings grouped by severity, optionally restricted to a subset of session
    /// ids. Every severity level is present in the result, zero when none match.
    async fn count_by_severity(
        &self,
        ids: Option<&[String]>,
    ) -> Result<std::collections::BTreeMap<crate::scan::Severity, i64>> {
        let mut builder: QueryBuilder<Sqlite> =
            QueryBuilder::new("SELECT severity, COUNT(*) AS count FROM findings");
        if let Some(ids) = ids {
            builder.push(" WHERE session_id IN (");
            let mut separated = builder.separated(", ");
            for id in ids {
                separated.push_bind(id);
            }
            separated.push_unseparated(")");
        }
        builder.push(" GROUP BY severity");

        let rows = builder.build().fetch_all(&self.pool).await?;
        let mut counts = severity_counts_zeroed();
        for row in &rows {
            let severity = records::severity_from_str(&row.try_get::<String, _>("severity")?)?;
            let count: i64 = row.try_get("count")?;
            counts.insert(severity, count);
        }
        Ok(counts)
    }
}

/// The `findings` columns selected when reconstructing a [`StoredFinding`].
const FINDING_COLUMNS_SELECT: &str = "SELECT id, finding_id, scanner_id, status, severity, title, \
     description, recommendations, target_json, evidence_json, timestamp FROM findings";

/// The `sessions` columns selected when reconstructing a [`StoredSession`],
/// terminated with the `session_id = ?` predicate for single-row fetches.
const SESSION_COLUMNS_SELECT: &str = "SELECT session_id, status, targets_json, scanners_json, \
     start_time, end_time, total_requests, error_count, created_at, updated_at \
     FROM sessions WHERE session_id = ?";

/// As [`SESSION_COLUMNS_SELECT`] but without a predicate, for list queries.
const SESSION_COLUMNS_SELECT_ALL: &str = "SELECT id, session_id, status, targets_json, \
     scanners_json, start_time, end_time, total_requests, error_count, created_at, updated_at \
     FROM sessions";

/// Reconstruct a [`StoredSession`] from a row.
fn row_to_session(row: &SqliteRow) -> Result<StoredSession> {
    let session_id = parse_uuid(&row.try_get::<String, _>("session_id")?)?;
    let status = records::session_status_from_str(&row.try_get::<String, _>("status")?)?;
    let targets = from_json(&row.try_get::<String, _>("targets_json")?)?;
    let scanner_ids = from_json(&row.try_get::<String, _>("scanners_json")?)?;
    let start_time: Option<DateTime<Utc>> = row.try_get("start_time")?;
    let end_time: Option<DateTime<Utc>> = row.try_get("end_time")?;
    let total_requests: i64 = row.try_get("total_requests")?;
    let error_count: i64 = row.try_get("error_count")?;
    let created_at: DateTime<Utc> = row.try_get("created_at")?;
    let updated_at: DateTime<Utc> = row.try_get("updated_at")?;

    Ok(StoredSession {
        record: SessionRecord {
            session_id,
            status,
            targets,
            scanner_ids,
            start_time,
            end_time,
            total_requests,
            error_count,
        },
        created_at,
        updated_at,
    })
}

/// Reconstruct a [`StoredFinding`] from a row.
fn row_to_finding(row: &SqliteRow) -> Result<StoredFinding> {
    let id: i64 = row.try_get("id")?;
    let finding_id = parse_uuid(&row.try_get::<String, _>("finding_id")?)?;
    let scanner_id: String = row.try_get("scanner_id")?;
    let status = records::status_from_str(&row.try_get::<String, _>("status")?)?;
    let severity = records::severity_from_str(&row.try_get::<String, _>("severity")?)?;
    let title: String = row.try_get("title")?;
    let description: Option<String> = row.try_get("description")?;
    let recommendations: Option<String> = row.try_get("recommendations")?;
    let target = from_json(&row.try_get::<String, _>("target_json")?)?;
    let evidence = match row.try_get::<Option<String>, _>("evidence_json")? {
        Some(raw) => Some(from_json(&raw)?),
        None => None,
    };
    let timestamp: DateTime<Utc> = row.try_get("timestamp")?;

    let finding = Finding {
        id: Some(id),
        scanner_id,
        target,
        severity,
        status,
        title,
        description,
        evidence,
        recommendations,
        timestamp,
    };
    Ok(StoredFinding {
        finding_id,
        finding,
    })
}

/// Serialize a value to a JSON string, mapping failures into a persistence error.
fn to_json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value)
        .map_err(|e| Error::Persistence(format!("failed to serialize stored field: {e}")))
}

/// Deserialize a JSON string from the store, mapping failures into a persistence
/// error.
fn from_json<T: serde::de::DeserializeOwned>(raw: &str) -> Result<T> {
    serde_json::from_str(raw)
        .map_err(|e| Error::Persistence(format!("failed to deserialize stored field: {e}")))
}

/// Parse a uuid read from the store.
fn parse_uuid(value: &str) -> Result<Uuid> {
    Uuid::parse_str(value)
        .map_err(|e| Error::Persistence(format!("invalid uuid {value:?} in store: {e}")))
}

/// Escape LIKE metacharacters so a free-text query matches them literally (used
/// with `ESCAPE '\'`).
fn escape_like(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

// `sqlx` failures map into the shared error model as `Persistence`, so the
// persistence methods can use `?` directly. These impls live here (not in
// `error`) to keep the error module free of the `sqlx` dependency.
impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {
        Error::Persistence(err.to_string())
    }
}

impl From<sqlx::migrate::MigrateError> for Error {
    fn from(err: sqlx::migrate::MigrateError) -> Self {
        Error::Persistence(format!("migration failed: {err}"))
    }
}
