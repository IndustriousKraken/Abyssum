//! Durable storage for scan sessions and findings.
//!
//! [`DatabaseManager`] owns one async SQLite connection pool ([`sqlx::SqlitePool`])
//! and is the single component orchestration and the surfaces call to persist and
//! query results. Scanners never touch it directly — they return findings up to
//! the engine, which persists them. The pool is cheaply cloneable, so the manager
//! is shared by `Clone`-ing the pool internally where needed.
//!
//! The store is **ownership-blind**: it has no notion of which user owns a
//! session. The `authentication` change (c02) layers ownership on top via its own
//! migration and adds owner-scoped queries by supplying a subset of session ids to
//! [`DatabaseManager::summary`].
//!
//! ## Schema and migrations
//!
//! The schema lives in versioned SQL files under `migrations/`, embedded at
//! compile time by [`sqlx::migrate!`] and applied idempotently on
//! [`connect`](DatabaseManager::connect) via sqlx's `_sqlx_migrations` tracking
//! table. Re-running against an already-current store is a no-op; later changes
//! extend the schema with their own additive migration files.
//!
//! ## Identifiers
//!
//! A [`ScanSession`] is addressed by its public [`Uuid`]. A [`Finding`] is
//! addressed by the stable [`FindingId`] (an `i64`) that [`save_finding`] assigns
//! on save and stamps into [`Finding::id`]; it is unique, never reused, and stable
//! across retrieval and restart. (The a03 design sketch named a uuid here, but the
//! canonical `Finding` type — owned by orchestration — carries an `i64` id, so the
//! row's autoincrement primary key *is* that stable identifier.)
//!
//! [`save_finding`]: DatabaseManager::save_finding

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteRow,
};
use sqlx::{QueryBuilder, Row, Sqlite};
use uuid::Uuid;

use crate::config::Config;
use crate::error::{db_err, Error, Result};
use crate::scan::{Finding, FindingId, ScanSession, SessionStatus, Severity, Status, Target};

/// Migrations embedded at compile time from `abyssum-core/migrations/`. Applied
/// on startup; sqlx tracks which have run, so applying them again is a no-op.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Default cap on rows returned by [`DatabaseManager::search_findings`] when the
/// filter does not request its own limit. Keeps a surface from accidentally
/// loading an unbounded result set.
pub const DEFAULT_SEARCH_LIMIT: i64 = 1000;

/// Hard ceiling on rows returned by a single query, regardless of the limit a
/// caller requests. A filter (or `list_sessions` page size) asking for more than
/// this is clamped down to it, so even an explicit `i64::MAX` can never load an
/// unbounded result set into memory. Set well above [`DEFAULT_SEARCH_LIMIT`] so
/// it only bites pathological requests, not ordinary paging.
pub const MAX_SEARCH_LIMIT: i64 = 10_000;

/// Owns the connection pool to the result store and exposes async persistence and
/// query operations over sessions and findings.
#[derive(Debug, Clone)]
pub struct DatabaseManager {
    pool: SqlitePool,
}

impl DatabaseManager {
    /// Open (creating if absent) the store at `path`, ensuring its parent
    /// directory exists, apply any pending migrations, then seed the curated
    /// reference data (wordlists + the User-Agent pool) before returning.
    ///
    /// Seeding is idempotent (see [`seed_reference_data`]), so reopening an
    /// already-populated store is a no-op — this is the first-run self-seeding
    /// path, and it runs regardless of how Abyssum was installed.
    ///
    /// The path is the resolved `database.path`; see [`connect_from_config`]. A
    /// failure to create the directory, open the pool, migrate, or seed surfaces
    /// as [`Error::Database`] (or [`Error::Io`] for the directory).
    ///
    /// [`connect_from_config`]: DatabaseManager::connect_from_config
    /// [`seed_reference_data`]: DatabaseManager::seed_reference_data
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();

        // Create the parent directory if the configured path nests the file (e.g.
        // the default `data/abyssum.db`). A bare filename has no parent to make.
        // Use the async filesystem API so this `async fn` never issues a blocking
        // syscall on the executor — `connect` is a startup path today, but keeping
        // it await-friendly means it stays safe to call from any async context.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await?;
            }
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            // Enforce the findings -> sessions foreign key so a deleted session
            // can never leave orphaned findings (belt-and-suspenders alongside the
            // explicit transactional delete).
            .foreign_keys(true)
            // WAL improves concurrent read/write behaviour for the pooled access
            // pattern; a busy timeout avoids spurious "database is locked" errors.
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect_with(options)
            .await
            .map_err(|e| {
                Error::Database(format!(
                    "failed to open database at {}: {e}",
                    path.display()
                ))
            })?;

        MIGRATOR
            .run(&pool)
            .await
            .map_err(|e| Error::Database(format!("failed to apply migrations: {e}")))?;

        let manager = Self { pool };
        manager.seed_reference_data().await?;
        Ok(manager)
    }

    /// Open the store at the path resolved from `config.database.path`.
    pub async fn connect_from_config(config: &Config) -> Result<Self> {
        Self::connect(&config.database.path).await
    }

    /// The underlying connection pool, for components that need to share it.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Seed the curated reference data (wordlists + the User-Agent pool) from the
    /// bundled assets, idempotently. [`connect`] calls this on open so a fresh
    /// store is populated on first run; it is also exposed so an installer or CLI
    /// can invoke seeding explicitly (e.g. an `abyssum init` / `--seed` path).
    /// Running it against an already-seeded store inserts nothing.
    ///
    /// [`connect`]: DatabaseManager::connect
    pub async fn seed_reference_data(&self) -> Result<()> {
        crate::seed::ReferenceStore::new(self.pool.clone())
            .seed()
            .await
    }

    /// A [`ReferenceStore`] over this manager's pool, for reading the seeded
    /// wordlists and User-Agent pool.
    ///
    /// [`ReferenceStore`]: crate::seed::ReferenceStore
    pub fn reference_store(&self) -> crate::seed::ReferenceStore {
        crate::seed::ReferenceStore::new(self.pool.clone())
    }

    /// Close the pool, flushing and releasing all connections. Optional — dropping
    /// the manager also closes it — but useful in tests that reopen the same file.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    // --- Sessions ---------------------------------------------------------

    /// Create or update a session, keyed by its public id (an upsert). Re-saving
    /// the same `session_id` updates the existing row in place — advancing its
    /// status, timing, and counts — rather than inserting a duplicate, and leaves
    /// the original `created_at` (the ordering key) untouched.
    ///
    /// Findings are persisted separately via [`save_finding`]; this writes only the
    /// session's own metadata.
    ///
    /// [`save_finding`]: DatabaseManager::save_finding
    pub async fn save_session(&self, session: &ScanSession) -> Result<()> {
        let targets_json = serde_json::to_string(&session.targets).map_err(db_err)?;
        let scanners_json = serde_json::to_string(&session.scanner_ids).map_err(db_err)?;

        sqlx::query(
            "INSERT INTO sessions \
               (session_id, status, targets_json, scanners_json, error_count, \
                completed_units, total_units, started_at, finished_at, updated_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) \
             ON CONFLICT(session_id) DO UPDATE SET \
               status          = excluded.status, \
               targets_json    = excluded.targets_json, \
               scanners_json   = excluded.scanners_json, \
               error_count     = excluded.error_count, \
               completed_units = excluded.completed_units, \
               total_units     = excluded.total_units, \
               started_at      = excluded.started_at, \
               finished_at     = excluded.finished_at, \
               updated_at      = CURRENT_TIMESTAMP",
        )
        .bind(session.id.to_string())
        .bind(session_status_str(session.status))
        .bind(targets_json)
        .bind(scanners_json)
        .bind(count_to_i64(session.error_count))
        .bind(count_to_i64(session.completed_units))
        .bind(count_to_i64(session.total_units))
        .bind(session.started_at)
        .bind(session.finished_at)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(())
    }

    /// Fetch a single session by id, **together with its stored findings**
    /// (ordered by timestamp). Returns `None` when no session has that id.
    pub async fn get_session(&self, session_id: Uuid) -> Result<Option<ScanSession>> {
        let row = sqlx::query(SESSION_COLUMNS_SELECT)
            .bind(session_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;

        let Some(row) = row else {
            return Ok(None);
        };

        let mut session = row_to_session(&row)?;
        session.findings = self.get_findings(session_id).await?;
        Ok(Some(session))
    }

    /// List stored sessions most-recently-created first, paged by `limit` and
    /// `offset`. The returned sessions carry their metadata only (an empty
    /// `findings` list); load a session's findings with [`get_session`] or
    /// [`get_findings`].
    ///
    /// A non-positive `limit` falls back to [`DEFAULT_SEARCH_LIMIT`], a `limit`
    /// above [`MAX_SEARCH_LIMIT`] is clamped down to it, and a negative `offset` is
    /// treated as `0`, mirroring [`search_findings`]: SQLite reads a negative
    /// `LIMIT` as "no limit", so binding one verbatim would silently return an
    /// unbounded result set. Clamping here keeps every listing bounded even when a
    /// caller passes a stray negative page size or an enormous one.
    ///
    /// [`get_session`]: DatabaseManager::get_session
    /// [`get_findings`]: DatabaseManager::get_findings
    /// [`search_findings`]: DatabaseManager::search_findings
    pub async fn list_sessions(&self, limit: i64, offset: i64) -> Result<Vec<ScanSession>> {
        let rows = sqlx::query(
            "SELECT session_id, status, targets_json, scanners_json, error_count, \
                    completed_units, total_units, started_at, finished_at \
             FROM sessions \
             ORDER BY created_at DESC, id DESC \
             LIMIT ? OFFSET ?",
        )
        .bind(resolve_search_limit(Some(limit)))
        .bind(offset.max(0))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        rows.iter().map(row_to_session).collect()
    }

    // --- Findings ---------------------------------------------------------

    /// Save a finding under `session_id`, assigning and returning its stable
    /// [`FindingId`]. The scanner id, target (lossless), status, severity, title,
    /// description, recommendations, evidence, and timestamp are all retained.
    pub async fn save_finding(&self, session_id: Uuid, finding: &Finding) -> Result<FindingId> {
        let target_json = serde_json::to_string(&finding.target).map_err(db_err)?;
        let target_full_url = finding.target.full_url().to_string();
        let evidence_json = match &finding.evidence {
            Some(value) => Some(serde_json::to_string(value).map_err(db_err)?),
            None => None,
        };

        let result = sqlx::query(
            "INSERT INTO findings \
               (session_id, scanner_id, status, severity, title, description, \
                recommendations, target_json, target_full_url, evidence_json, timestamp) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(session_id.to_string())
        .bind(finding.scanner_id.as_str())
        .bind(status_str(finding.status))
        .bind(severity_str(finding.severity))
        .bind(finding.title.as_str())
        .bind(finding.description.as_deref())
        .bind(finding.recommendations.as_deref())
        .bind(target_json)
        .bind(target_full_url)
        .bind(evidence_json)
        .bind(finding.timestamp)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        Ok(result.last_insert_rowid())
    }

    /// All findings stored under `session_id`, ordered by timestamp (then id for a
    /// stable tie-break). Each finding's [`id`](Finding::id) is its stable
    /// [`FindingId`].
    pub async fn get_findings(&self, session_id: Uuid) -> Result<Vec<Finding>> {
        let rows = sqlx::query(&format!(
            "{FINDING_COLUMNS_SELECT} WHERE session_id = ? ORDER BY timestamp ASC, id ASC"
        ))
        .bind(session_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        rows.iter().map(row_to_finding).collect()
    }

    // --- Query / filter ---------------------------------------------------

    /// Search findings, applying any subset of the [`FindingFilter`] criteria
    /// (status, severity, scanner id, target, free-text over title/description, a
    /// session id, and a `from`/`to` date range over the timestamp), combined with
    /// `AND`. Results are ordered newest-first and capped at the filter's limit (or
    /// [`DEFAULT_SEARCH_LIMIT`] when unset), never exceeding [`MAX_SEARCH_LIMIT`].
    pub async fn search_findings(&self, filter: &FindingFilter) -> Result<Vec<Finding>> {
        let mut qb: QueryBuilder<Sqlite> =
            QueryBuilder::new(format!("{FINDING_COLUMNS_SELECT} WHERE 1 = 1"));

        if let Some(session_id) = filter.session_id {
            qb.push(" AND session_id = ")
                .push_bind(session_id.to_string());
        }
        if let Some(status) = filter.status {
            qb.push(" AND status = ").push_bind(status_str(status));
        }
        if let Some(severity) = filter.severity {
            qb.push(" AND severity = ")
                .push_bind(severity_str(severity));
        }
        if let Some(scanner_id) = &filter.scanner_id {
            qb.push(" AND scanner_id = ").push_bind(scanner_id.clone());
        }
        if let Some(target) = &filter.target {
            qb.push(" AND target_full_url = ").push_bind(target.clone());
        }
        if let Some(query) = &filter.query {
            let pattern = format!("%{}%", escape_like(query));
            qb.push(" AND (title LIKE ").push_bind(pattern.clone());
            qb.push(" ESCAPE '\\' OR description LIKE ")
                .push_bind(pattern);
            qb.push(" ESCAPE '\\')");
        }
        if let Some(from) = filter.from {
            qb.push(" AND timestamp >= ").push_bind(from);
        }
        if let Some(to) = filter.to {
            qb.push(" AND timestamp <= ").push_bind(to);
        }

        qb.push(" ORDER BY timestamp DESC, id DESC LIMIT ");
        qb.push_bind(resolve_search_limit(filter.limit));

        let rows = qb.build().fetch_all(&self.pool).await.map_err(db_err)?;
        rows.iter().map(row_to_finding).collect()
    }

    /// Summary counts over stored data: total sessions, total findings, and a
    /// per-severity finding breakdown. When `session_ids` is `Some`, every count is
    /// restricted to that subset of sessions (an empty subset counts nothing); when
    /// `None`, the whole store is summarized. This is how a surface presents
    /// owner-scoped statistics while the store stays ownership-blind.
    pub async fn summary(&self, session_ids: Option<&[Uuid]>) -> Result<Summary> {
        // An explicit, empty restriction matches nothing — short-circuit so we
        // never build an empty `IN ()` clause.
        if matches!(session_ids, Some(ids) if ids.is_empty()) {
            return Ok(Summary::empty());
        }
        let ids: Option<Vec<String>> =
            session_ids.map(|ids| ids.iter().map(Uuid::to_string).collect());

        // Session count.
        let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new("SELECT COUNT(*) FROM sessions");
        if let Some(ids) = &ids {
            qb.push(" WHERE session_id IN (");
            push_in_list(&mut qb, ids);
            qb.push(")");
        }
        let session_count: i64 = qb
            .build_query_scalar()
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;

        // Findings grouped by severity.
        let mut qb: QueryBuilder<Sqlite> =
            QueryBuilder::new("SELECT severity, COUNT(*) FROM findings");
        if let Some(ids) = &ids {
            qb.push(" WHERE session_id IN (");
            push_in_list(&mut qb, ids);
            qb.push(")");
        }
        qb.push(" GROUP BY severity");
        let rows = qb.build().fetch_all(&self.pool).await.map_err(db_err)?;

        let mut by_severity = Summary::zeroed_severity_map();
        let mut finding_count = 0i64;
        for row in &rows {
            let severity_text: String = row.try_get(0).map_err(db_err)?;
            let count: i64 = row.try_get(1).map_err(db_err)?;
            finding_count += count;
            // A severity the code doesn't recognize is skipped from the breakdown
            // but still counted in the total — the store should never hold one.
            if let Ok(severity) = parse_severity(&severity_text) {
                by_severity.insert(severity, count);
            }
        }

        Ok(Summary {
            session_count,
            finding_count,
            by_severity,
        })
    }

    // --- Deletion ---------------------------------------------------------

    /// Delete a session and all of its findings as one atomic transaction.
    /// Returns `true` if a session was removed, `false` if none had that id. Other
    /// sessions and their findings are unaffected.
    pub async fn delete_session(&self, session_id: Uuid) -> Result<bool> {
        let id = session_id.to_string();
        let mut tx = self.pool.begin().await.map_err(db_err)?;

        sqlx::query("DELETE FROM findings WHERE session_id = ?")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        let result = sqlx::query("DELETE FROM sessions WHERE session_id = ?")
            .bind(&id)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;

        tx.commit().await.map_err(db_err)?;
        Ok(result.rows_affected() > 0)
    }
}

/// Column list + table for selecting a full session row (without findings).
const SESSION_COLUMNS_SELECT: &str = "SELECT session_id, status, targets_json, scanners_json, \
     error_count, completed_units, total_units, started_at, finished_at \
     FROM sessions WHERE session_id = ?";

/// Column list + table for selecting full finding rows; callers append the
/// `WHERE`/`ORDER BY`/`LIMIT` clauses.
const FINDING_COLUMNS_SELECT: &str = "SELECT id, session_id, scanner_id, status, severity, title, \
     description, recommendations, target_json, target_full_url, evidence_json, timestamp \
     FROM findings";

/// The criteria [`DatabaseManager::search_findings`] filters on. Every field is
/// optional; an all-`None` filter matches every finding (up to the limit). Build
/// with [`FindingFilter::new`] and the `by_*` setters, or as a struct literal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FindingFilter {
    /// Restrict to one session.
    pub session_id: Option<Uuid>,
    /// Restrict to one status classification.
    pub status: Option<Status>,
    /// Restrict to one severity level.
    pub severity: Option<Severity>,
    /// Restrict to findings produced by one scanner.
    pub scanner_id: Option<String>,
    /// Restrict to findings against one target (matched on the target's full URL).
    pub target: Option<String>,
    /// Free-text query matched (case-insensitively) against title or description.
    pub query: Option<String>,
    /// Inclusive lower bound on the finding timestamp.
    pub from: Option<DateTime<Utc>>,
    /// Inclusive upper bound on the finding timestamp.
    pub to: Option<DateTime<Utc>>,
    /// Maximum rows to return (defaults to [`DEFAULT_SEARCH_LIMIT`], capped at
    /// [`MAX_SEARCH_LIMIT`]).
    pub limit: Option<i64>,
}

impl FindingFilter {
    /// An empty filter (matches everything up to the default limit).
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to one session.
    pub fn by_session(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Restrict to one status.
    pub fn by_status(mut self, status: Status) -> Self {
        self.status = Some(status);
        self
    }

    /// Restrict to one severity.
    pub fn by_severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Restrict to one scanner id.
    pub fn by_scanner(mut self, scanner_id: impl Into<String>) -> Self {
        self.scanner_id = Some(scanner_id.into());
        self
    }

    /// Restrict to findings against one target (its full URL).
    pub fn by_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Restrict to findings whose title or description matches `query`.
    pub fn matching(mut self, query: impl Into<String>) -> Self {
        self.query = Some(query.into());
        self
    }

    /// Restrict to findings at or after `from`.
    pub fn from(mut self, from: DateTime<Utc>) -> Self {
        self.from = Some(from);
        self
    }

    /// Restrict to findings at or before `to`.
    pub fn to(mut self, to: DateTime<Utc>) -> Self {
        self.to = Some(to);
        self
    }

    /// Cap the number of rows returned.
    pub fn limit(mut self, limit: i64) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Aggregate counts over the store, optionally restricted to a subset of sessions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Number of stored sessions in scope.
    pub session_count: i64,
    /// Number of stored findings in scope.
    pub finding_count: i64,
    /// Findings-in-scope per severity level (every level present, zero if none).
    pub by_severity: BTreeMap<Severity, i64>,
}

impl Summary {
    /// An all-zero summary (every severity present at 0).
    fn empty() -> Self {
        Self {
            session_count: 0,
            finding_count: 0,
            by_severity: Self::zeroed_severity_map(),
        }
    }

    /// A map with every severity level present at count 0, so the breakdown always
    /// reports all levels.
    fn zeroed_severity_map() -> BTreeMap<Severity, i64> {
        let mut map = BTreeMap::new();
        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            map.insert(severity, 0);
        }
        map
    }
}

/// Convert a scan-scale `usize` count to the `i64` SQLite stores. These are
/// scanner-target unit and error counts that never approach `i64::MAX` in
/// practice; saturating (rather than `as`-casting) just makes the conversion
/// total so an out-of-range value can never silently wrap to a negative.
fn count_to_i64(count: usize) -> i64 {
    i64::try_from(count).unwrap_or(i64::MAX)
}

/// Convert a stored count back to `usize`, clamping a (never-expected) negative
/// value to `0` rather than wrapping it to a huge `usize` the way an `as` cast
/// would. The store only ever writes non-negative counts via [`count_to_i64`];
/// this guards the read path against a corrupted or externally-edited row.
fn count_to_usize(count: i64) -> usize {
    usize::try_from(count).unwrap_or(0)
}

/// Push a comma-separated, parameter-bound list of ids into an `IN (...)` clause.
fn push_in_list(qb: &mut QueryBuilder<'_, Sqlite>, ids: &[String]) {
    let mut separated = qb.separated(", ");
    for id in ids {
        separated.push_bind(id.clone());
    }
}

/// Resolve the effective search limit, bounding it on both ends. A missing limit,
/// or a non-positive one, falls back to [`DEFAULT_SEARCH_LIMIT`]: SQLite treats a
/// negative `LIMIT` as "no limit", so binding one verbatim would silently bypass
/// the cap and return an unbounded result set. A positive limit is honored but
/// clamped down to [`MAX_SEARCH_LIMIT`], so even an explicit `i64::MAX` cannot
/// load millions of rows into memory. Clamping here keeps every search bounded
/// even when a caller constructs a filter with a stray `Some(-1)`, `Some(0)`, or
/// an enormous limit.
fn resolve_search_limit(limit: Option<i64>) -> i64 {
    match limit {
        Some(limit) if limit > 0 => limit.min(MAX_SEARCH_LIMIT),
        _ => DEFAULT_SEARCH_LIMIT,
    }
}

/// Escape the LIKE metacharacters in user free-text so a query containing `%` or
/// `_` matches literally (paired with `ESCAPE '\'` in the SQL).
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

/// Map a session row (the `SESSION_COLUMNS_SELECT`/`list_sessions` projection) into
/// a [`ScanSession`] with an empty `findings` list.
fn row_to_session(row: &SqliteRow) -> Result<ScanSession> {
    let session_id: String = row.try_get("session_id").map_err(db_err)?;
    let id = Uuid::parse_str(&session_id).map_err(db_err)?;
    let status = parse_session_status(&row.try_get::<String, _>("status").map_err(db_err)?)?;
    let targets: Vec<Target> =
        serde_json::from_str(&row.try_get::<String, _>("targets_json").map_err(db_err)?)
            .map_err(db_err)?;
    let scanner_ids: Vec<String> =
        serde_json::from_str(&row.try_get::<String, _>("scanners_json").map_err(db_err)?)
            .map_err(db_err)?;
    let error_count: i64 = row.try_get("error_count").map_err(db_err)?;
    let completed_units: i64 = row.try_get("completed_units").map_err(db_err)?;
    let total_units: i64 = row.try_get("total_units").map_err(db_err)?;
    let started_at: Option<DateTime<Utc>> = row.try_get("started_at").map_err(db_err)?;
    let finished_at: Option<DateTime<Utc>> = row.try_get("finished_at").map_err(db_err)?;

    Ok(ScanSession {
        id,
        targets,
        scanner_ids,
        status,
        findings: Vec::new(),
        error_count: count_to_usize(error_count),
        completed_units: count_to_usize(completed_units),
        total_units: count_to_usize(total_units),
        started_at,
        finished_at,
    })
}

/// Map a finding row (the `FINDING_COLUMNS_SELECT` projection) into a [`Finding`],
/// stamping its stored stable id.
fn row_to_finding(row: &SqliteRow) -> Result<Finding> {
    let id: i64 = row.try_get("id").map_err(db_err)?;
    let scanner_id: String = row.try_get("scanner_id").map_err(db_err)?;
    let status = parse_status(&row.try_get::<String, _>("status").map_err(db_err)?)?;
    let severity = parse_severity(&row.try_get::<String, _>("severity").map_err(db_err)?)?;
    let title: String = row.try_get("title").map_err(db_err)?;
    let description: Option<String> = row.try_get("description").map_err(db_err)?;
    let recommendations: Option<String> = row.try_get("recommendations").map_err(db_err)?;
    let target: Target =
        serde_json::from_str(&row.try_get::<String, _>("target_json").map_err(db_err)?)
            .map_err(db_err)?;
    let evidence = match row
        .try_get::<Option<String>, _>("evidence_json")
        .map_err(db_err)?
    {
        Some(text) => Some(serde_json::from_str(&text).map_err(db_err)?),
        None => None,
    };
    let timestamp: DateTime<Utc> = row.try_get("timestamp").map_err(db_err)?;

    Ok(Finding {
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
    })
}

/// The on-disk spelling of a [`SessionStatus`] (matches its serde lowercase name).
fn session_status_str(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Pending => "pending",
        SessionStatus::Running => "running",
        SessionStatus::Completed => "completed",
        SessionStatus::Cancelled => "cancelled",
        SessionStatus::Errored => "errored",
    }
}

/// Parse a stored session status, rejecting an unknown value as a store error.
fn parse_session_status(text: &str) -> Result<SessionStatus> {
    Ok(match text {
        "pending" => SessionStatus::Pending,
        "running" => SessionStatus::Running,
        "completed" => SessionStatus::Completed,
        "cancelled" => SessionStatus::Cancelled,
        "errored" => SessionStatus::Errored,
        other => {
            return Err(Error::Database(format!(
                "unknown session status in store: {other:?}"
            )))
        }
    })
}

/// The on-disk spelling of a [`Status`] (matches its serde lowercase name).
fn status_str(status: Status) -> &'static str {
    match status {
        Status::Vulnerable => "vulnerable",
        Status::Safe => "safe",
        Status::Info => "info",
    }
}

/// Parse a stored finding status, rejecting an unknown value as a store error.
fn parse_status(text: &str) -> Result<Status> {
    Ok(match text {
        "vulnerable" => Status::Vulnerable,
        "safe" => Status::Safe,
        "info" => Status::Info,
        other => {
            return Err(Error::Database(format!(
                "unknown finding status in store: {other:?}"
            )))
        }
    })
}

/// The on-disk spelling of a [`Severity`] (matches its serde lowercase name).
fn severity_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Parse a stored severity, rejecting an unknown value as a store error.
fn parse_severity(text: &str) -> Result<Severity> {
    Ok(match text {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        other => {
            return Err(Error::Database(format!(
                "unknown severity in store: {other:?}"
            )))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_strings_round_trip_through_parse() {
        for status in [Status::Vulnerable, Status::Safe, Status::Info] {
            assert_eq!(parse_status(status_str(status)).unwrap(), status);
        }
    }

    #[test]
    fn severity_strings_round_trip_through_parse() {
        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert_eq!(parse_severity(severity_str(severity)).unwrap(), severity);
        }
    }

    #[test]
    fn session_status_strings_round_trip_through_parse() {
        for status in [
            SessionStatus::Pending,
            SessionStatus::Running,
            SessionStatus::Completed,
            SessionStatus::Cancelled,
            SessionStatus::Errored,
        ] {
            assert_eq!(
                parse_session_status(session_status_str(status)).unwrap(),
                status
            );
        }
    }

    #[test]
    fn on_disk_spellings_match_serde_names() {
        // The stored text must match the shared serde lowercase vocabulary so a
        // value written here reads back the same as one serialized elsewhere.
        assert_eq!(
            severity_str(Severity::Critical),
            serde_json::to_value(Severity::Critical)
                .unwrap()
                .as_str()
                .unwrap()
        );
        assert_eq!(
            status_str(Status::Vulnerable),
            serde_json::to_value(Status::Vulnerable)
                .unwrap()
                .as_str()
                .unwrap()
        );
        assert_eq!(
            session_status_str(SessionStatus::Running),
            serde_json::to_value(SessionStatus::Running)
                .unwrap()
                .as_str()
                .unwrap()
        );
    }

    #[test]
    fn unknown_stored_values_are_database_errors() {
        assert!(matches!(parse_status("bogus"), Err(Error::Database(_))));
        assert!(matches!(parse_severity("bogus"), Err(Error::Database(_))));
        assert!(matches!(
            parse_session_status("bogus"),
            Err(Error::Database(_))
        ));
    }

    #[test]
    fn escape_like_escapes_metacharacters() {
        assert_eq!(escape_like("a%b_c\\d"), "a\\%b\\_c\\\\d");
        assert_eq!(escape_like("plain"), "plain");
    }

    #[test]
    fn search_limit_clamps_missing_non_positive_and_oversized() {
        assert_eq!(resolve_search_limit(Some(25)), 25);
        assert_eq!(resolve_search_limit(None), DEFAULT_SEARCH_LIMIT);
        // A negative LIMIT is "no limit" in SQLite; a zero limit is degenerate.
        // Both must fall back to the cap rather than returning an unbounded set.
        assert_eq!(resolve_search_limit(Some(-1)), DEFAULT_SEARCH_LIMIT);
        assert_eq!(resolve_search_limit(Some(0)), DEFAULT_SEARCH_LIMIT);
        // A positive limit at or below the ceiling is honored verbatim; one above
        // it (up to i64::MAX) is clamped down so it can never load an unbounded set.
        assert_eq!(
            resolve_search_limit(Some(MAX_SEARCH_LIMIT)),
            MAX_SEARCH_LIMIT
        );
        assert_eq!(
            resolve_search_limit(Some(MAX_SEARCH_LIMIT + 1)),
            MAX_SEARCH_LIMIT
        );
        assert_eq!(resolve_search_limit(Some(i64::MAX)), MAX_SEARCH_LIMIT);
    }

    #[test]
    fn summary_severity_map_starts_zeroed_with_all_levels() {
        let map = Summary::zeroed_severity_map();
        assert_eq!(map.len(), 5);
        assert!(map.values().all(|&count| count == 0));
        assert!(map.contains_key(&Severity::Critical));
    }

    #[test]
    fn count_conversions_round_trip_and_clamp_out_of_range() {
        // Scan-scale counts round-trip exactly through both conversions.
        for count in [0usize, 1, 42, 1_000_000] {
            assert_eq!(count_to_usize(count_to_i64(count)), count);
        }
        // A usize beyond i64::MAX saturates rather than wrapping negative.
        assert_eq!(count_to_i64(usize::MAX), i64::MAX);
        // A (never-expected) negative stored value clamps to 0 instead of
        // wrapping to a huge usize the way an `as` cast would.
        assert_eq!(count_to_usize(-1), 0);
        assert_eq!(count_to_usize(i64::MIN), 0);
    }
}
