//! The dedicated, persistent traffic store.
//!
//! Every exchange the proxy relays is captured into its own SQLite database —
//! separate from the scan result store — so proxy traffic and scan findings stay
//! cleanly separated (see `design.md`). The schema is a single `exchanges` table
//! indexed for query by endpoint, host, status, and time; parameter and header
//! names are queried through SQLite's JSON functions over per-row JSON columns.
//!
//! Capture is **asynchronous and best-effort**: the relay hands an exchange to a
//! bounded channel via [`CaptureSink::capture`] (which never awaits), and a
//! background writer task drains it into the store. A slow or failing store can
//! only fill the channel and drop captures — it can never stall the proxied client.

use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};
use sqlx::{QueryBuilder, Row, Sqlite};

use crate::analysis::{Flag, analyze};
use crate::error::{Error, Result};

/// Default cap on rows returned by [`TrafficStore::query`] when the query does not
/// set its own limit. Keeps a caller from accidentally loading an unbounded set.
pub const DEFAULT_QUERY_LIMIT: i64 = 1000;

/// One relayed request/response pair, as captured off the hot path. Bodies are
/// already truncated to the configured size limit by the time they reach here.
#[derive(Debug, Clone)]
pub struct CapturedExchange {
    /// Request method (`GET`, `POST`, …).
    pub method: String,
    /// Full request URL (`https://host/path?query`).
    pub url: String,
    /// Destination host (no port).
    pub host: String,
    /// Request path — the "endpoint" the store is queryable by.
    pub endpoint: String,
    /// Raw query string (without the leading `?`), if any.
    pub query: Option<String>,
    /// Distinct query-parameter names, for query-by-parameter.
    pub params: Vec<String>,
    /// Request headers, in wire order.
    pub req_headers: Vec<(String, String)>,
    /// Request body, truncated to the size limit.
    pub req_body: Vec<u8>,
    /// Whether [`req_body`](Self::req_body) was truncated.
    pub req_body_truncated: bool,
    /// Response status code.
    pub status: u16,
    /// Response headers, in wire order.
    pub resp_headers: Vec<(String, String)>,
    /// Response body, truncated to the size limit.
    pub resp_body: Vec<u8>,
    /// Whether [`resp_body`](Self::resp_body) was truncated.
    pub resp_body_truncated: bool,
    /// When the exchange started (request sent upstream).
    pub started_at: DateTime<Utc>,
    /// End-to-end duration in milliseconds.
    pub duration_ms: i64,
}

/// A stored exchange, as returned by [`TrafficStore::query`]. Carries its stable
/// row id plus everything captured, and the analysis (auto-flags + interest score)
/// persisted alongside it.
#[derive(Debug, Clone)]
pub struct StoredExchange {
    /// Stable, never-reused row id.
    pub id: i64,
    /// The captured exchange.
    pub exchange: CapturedExchange,
    /// Auto-detected security-relevant categories, persisted with the row.
    pub flags: Vec<Flag>,
    /// Additive interest score summed from [`flags`](Self::flags); higher ranks
    /// ahead in the triage view. A ranking aid, not a verdict.
    pub score: i64,
}

/// Criteria for [`TrafficStore::query`]. Every field is optional and combined with
/// `AND`; an all-`None` query returns the most recent exchanges up to the limit.
#[derive(Debug, Clone, Default)]
pub struct TrafficQuery {
    /// Exact request path.
    pub endpoint: Option<String>,
    /// A query-parameter name that must be present.
    pub param: Option<String>,
    /// A request-header name that must be present (matched case-insensitively).
    pub header: Option<String>,
    /// Exact response status code.
    pub status: Option<u16>,
    /// Exact destination host.
    pub host: Option<String>,
    /// Inclusive lower bound on the start time.
    pub from: Option<DateTime<Utc>>,
    /// Inclusive upper bound on the start time.
    pub to: Option<DateTime<Utc>>,
    /// An auto-flag category that must be present (e.g. `auth`, `idor`).
    pub flag: Option<String>,
    /// Order highest-interest first (by score) rather than newest first. This is
    /// the triage view: interesting traffic surfaces ahead of the noise.
    pub interest_first: bool,
    /// Maximum rows (defaults to [`DEFAULT_QUERY_LIMIT`]).
    pub limit: Option<i64>,
}

impl TrafficQuery {
    /// An empty query (matches everything up to the default limit).
    pub fn new() -> Self {
        Self::default()
    }
    /// Restrict to one endpoint (request path).
    pub fn by_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }
    /// Restrict to exchanges carrying a parameter named `name`.
    pub fn by_param(mut self, name: impl Into<String>) -> Self {
        self.param = Some(name.into());
        self
    }
    /// Restrict to exchanges carrying a request header named `name`.
    pub fn by_header(mut self, name: impl Into<String>) -> Self {
        self.header = Some(name.into());
        self
    }
    /// Restrict to one response status.
    pub fn by_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }
    /// Restrict to one destination host.
    pub fn by_host(mut self, host: impl Into<String>) -> Self {
        self.host = Some(host.into());
        self
    }
    /// Restrict to exchanges started at or after `from`.
    pub fn from(mut self, from: DateTime<Utc>) -> Self {
        self.from = Some(from);
        self
    }
    /// Restrict to exchanges started at or before `to`.
    pub fn to(mut self, to: DateTime<Utc>) -> Self {
        self.to = Some(to);
        self
    }
    /// Restrict to exchanges carrying the auto-flag `flag` (e.g. [`Flag::label`]).
    pub fn by_flag(mut self, flag: impl Into<String>) -> Self {
        self.flag = Some(flag.into());
        self
    }
    /// Surface highest-interest exchanges first (the triage ordering).
    pub fn interest_first(mut self) -> Self {
        self.interest_first = true;
        self
    }
}

/// Owns the connection pool to the traffic store and persists/queries exchanges.
/// Cheaply cloneable (the pool is shared).
#[derive(Debug, Clone)]
pub struct TrafficStore {
    pool: SqlitePool,
}

impl TrafficStore {
    /// Open (creating if absent) the store at `path`, ensuring its parent directory
    /// exists and the schema is present. Reopening an existing store is a no-op, so
    /// captured traffic survives process restart.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent).await?;
            // The store holds captured Authorization headers, cookies, and bodies —
            // lock its directory to the owner so no other user can read the DB (or
            // its `-wal`/`-shm` siblings, which hold uncommitted captures).
            restrict_to_owner(parent, 0o700).await?;
        }

        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .map_err(|e| Error::Store(format!("failed to open traffic store: {e}")))?;

        // The DB file exists once the pool connects — tighten it to owner-only so the
        // captured credentials it stores are never world-readable (defence in depth
        // behind the 0o700 directory above).
        restrict_to_owner(path, 0o600).await?;

        // ponytail: one table + a few indexes — a `CREATE TABLE IF NOT EXISTS` on
        // open is all "survive restart" needs; no migration framework for one table.
        sqlx::query(SCHEMA)
            .execute(&pool)
            .await
            .map_err(|e| Error::Store(format!("failed to initialise traffic store: {e}")))?;

        // A store captured by f01 (pre-analysis) lacks the analysis columns; add them
        // idempotently so an existing DB upgrades in place. A fresh table already has
        // them from SCHEMA, so tolerate the "duplicate column" error. The score index
        // is created here (not in SCHEMA) so it never precedes the column on an
        // upgraded DB.
        for stmt in [
            "ALTER TABLE exchanges ADD COLUMN flags_json TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE exchanges ADD COLUMN score INTEGER NOT NULL DEFAULT 0",
        ] {
            if let Err(e) = sqlx::query(stmt).execute(&pool).await
                && !e.to_string().contains("duplicate column")
            {
                return Err(Error::Store(format!(
                    "failed to migrate traffic store: {e}"
                )));
            }
        }
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_exchanges_score ON exchanges(score)")
            .execute(&pool)
            .await
            .map_err(|e| Error::Store(format!("failed to index traffic store: {e}")))?;

        Ok(Self { pool })
    }

    /// Spawn the background writer task and return the [`CaptureSink`] the relay
    /// hands exchanges to. The channel is bounded by `capacity`; once full, further
    /// captures are dropped (best-effort) rather than blocking the relay.
    pub fn spawn_writer(&self, capacity: usize) -> CaptureSink {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<CapturedExchange>(capacity.max(1));
        let store = self.clone();
        tokio::spawn(async move {
            while let Some(exchange) = rx.recv().await {
                if let Err(e) = store.record(&exchange).await {
                    // A failing store is best-effort: log and keep draining so the
                    // channel does not back up and start dropping the client's view.
                    tracing::warn!(error = %e, "failed to persist captured exchange");
                }
            }
        });
        CaptureSink { tx }
    }

    /// Persist one exchange, returning its assigned row id. The exchange is analysed
    /// (auto-flagged + scored) here, in the async writer — off the relay's hot path —
    /// and its flags/score are stored with the row so the triage view is queryable
    /// and stable across restarts.
    pub async fn record(&self, ex: &CapturedExchange) -> Result<i64> {
        let params_json = serde_json::to_string(&ex.params).map_err(store_err)?;
        let req_headers_json = headers_to_json(&ex.req_headers).map_err(store_err)?;
        let resp_headers_json = headers_to_json(&ex.resp_headers).map_err(store_err)?;

        let analysis = analyze(ex);
        let flags_json = flags_to_json(&analysis.flags).map_err(store_err)?;

        let result = sqlx::query(
            "INSERT INTO exchanges \
               (method, url, host, endpoint, query, params_json, req_headers_json, \
                req_body, req_body_truncated, status, resp_headers_json, resp_body, \
                resp_body_truncated, started_at, duration_ms, flags_json, score) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&ex.method)
        .bind(&ex.url)
        .bind(&ex.host)
        .bind(&ex.endpoint)
        .bind(ex.query.as_deref())
        .bind(params_json)
        .bind(req_headers_json)
        .bind(ex.req_body.as_slice())
        .bind(ex.req_body_truncated)
        .bind(i64::from(ex.status))
        .bind(resp_headers_json)
        .bind(ex.resp_body.as_slice())
        .bind(ex.resp_body_truncated)
        .bind(ex.started_at)
        .bind(ex.duration_ms)
        .bind(flags_json)
        .bind(analysis.score)
        .execute(&self.pool)
        .await
        .map_err(store_err)?;

        Ok(result.last_insert_rowid())
    }

    /// Fetch a single stored exchange by its row id (used by replay, which loads the
    /// captured request to re-issue, and by the read API's by-id lookup).
    pub async fn get(&self, id: i64) -> Result<Option<StoredExchange>> {
        let row = sqlx::query(&format!(
            "SELECT {EXCHANGE_COLUMNS} FROM exchanges WHERE id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(store_err)?;
        row.as_ref().map(row_to_exchange).transpose()
    }

    /// Query stored exchanges by any subset of the [`TrafficQuery`] dimensions,
    /// newest first, capped at the query's limit (default [`DEFAULT_QUERY_LIMIT`]).
    pub async fn query(&self, q: &TrafficQuery) -> Result<Vec<StoredExchange>> {
        let mut qb: QueryBuilder<Sqlite> = QueryBuilder::new(format!(
            "SELECT {EXCHANGE_COLUMNS} FROM exchanges WHERE 1 = 1"
        ));

        if let Some(endpoint) = &q.endpoint {
            qb.push(" AND endpoint = ").push_bind(endpoint.clone());
        }
        if let Some(host) = &q.host {
            qb.push(" AND host = ").push_bind(host.clone());
        }
        if let Some(status) = q.status {
            qb.push(" AND status = ").push_bind(i64::from(status));
        }
        if let Some(from) = q.from {
            qb.push(" AND started_at >= ").push_bind(from);
        }
        if let Some(to) = q.to {
            qb.push(" AND started_at <= ").push_bind(to);
        }
        if let Some(param) = &q.param {
            // Parameter names live in a JSON array; match presence via json_each.
            qb.push(" AND EXISTS (SELECT 1 FROM json_each(params_json) WHERE json_each.value = ")
                .push_bind(param.clone())
                .push(")");
        }
        if let Some(header) = &q.header {
            // Header names are the keys of a JSON object; match presence (names are
            // stored lowercased, so lowercase the needle).
            qb.push(
                " AND EXISTS (SELECT 1 FROM json_each(req_headers_json) WHERE json_each.key = ",
            )
            .push_bind(header.to_ascii_lowercase())
            .push(")");
        }
        if let Some(flag) = &q.flag {
            // Flag labels live in a JSON array; match presence via json_each.
            qb.push(" AND EXISTS (SELECT 1 FROM json_each(flags_json) WHERE json_each.value = ")
                .push_bind(flag.clone())
                .push(")");
        }

        // Triage view surfaces highest-interest first; default is newest first.
        if q.interest_first {
            qb.push(" ORDER BY score DESC, id DESC LIMIT ");
        } else {
            qb.push(" ORDER BY id DESC LIMIT ");
        }
        qb.push_bind(resolve_limit(q.limit));

        let rows = qb.build().fetch_all(&self.pool).await.map_err(store_err)?;
        rows.iter().map(row_to_exchange).collect()
    }

    /// Total number of stored exchanges (used by the CLI's status line and tests).
    pub async fn count(&self) -> Result<i64> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM exchanges")
            .fetch_one(&self.pool)
            .await
            .map_err(store_err)?;
        Ok(n)
    }

    /// Close the pool, releasing all connections. Optional (drop closes it too), but
    /// useful in tests that reopen the same file.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// The non-blocking handle the relay uses to hand exchanges to the writer task.
#[derive(Debug, Clone)]
pub struct CaptureSink {
    tx: tokio::sync::mpsc::Sender<CapturedExchange>,
}

impl CaptureSink {
    /// Hand an exchange to the async writer. **Never awaits and never blocks**: if
    /// the channel is full (writer behind) or closed, the capture is dropped and a
    /// warning logged, so the proxied client is never stalled by the store.
    pub fn capture(&self, exchange: CapturedExchange) {
        if let Err(err) = self.tx.try_send(exchange) {
            match err {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    tracing::warn!("traffic store behind — dropping captured exchange");
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    tracing::warn!("traffic store writer stopped — dropping captured exchange");
                }
            }
        }
    }
}

/// The column list projected by [`TrafficStore::query`] and [`TrafficStore::get`],
/// in the order [`row_to_exchange`] reads them. Kept in one place so the two read
/// paths cannot drift.
const EXCHANGE_COLUMNS: &str = "id, method, url, host, endpoint, query, params_json, \
    req_headers_json, req_body, req_body_truncated, status, resp_headers_json, resp_body, \
    resp_body_truncated, started_at, duration_ms, flags_json, score";

/// The full schema — one indexed table. `params_json` is a JSON array of parameter
/// names; `*_headers_json` are JSON objects keyed by lowercased header name.
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS exchanges (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    method              TEXT    NOT NULL,
    url                 TEXT    NOT NULL,
    host                TEXT    NOT NULL,
    endpoint            TEXT    NOT NULL,
    query               TEXT,
    params_json         TEXT    NOT NULL,
    req_headers_json    TEXT    NOT NULL,
    req_body            BLOB,
    req_body_truncated  INTEGER NOT NULL DEFAULT 0,
    status              INTEGER NOT NULL,
    resp_headers_json   TEXT    NOT NULL,
    resp_body           BLOB,
    resp_body_truncated INTEGER NOT NULL DEFAULT 0,
    started_at          TEXT    NOT NULL,
    duration_ms         INTEGER NOT NULL,
    flags_json          TEXT    NOT NULL DEFAULT '[]',
    score               INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_exchanges_endpoint   ON exchanges(endpoint);
CREATE INDEX IF NOT EXISTS idx_exchanges_host       ON exchanges(host);
CREATE INDEX IF NOT EXISTS idx_exchanges_status     ON exchanges(status);
CREATE INDEX IF NOT EXISTS idx_exchanges_started_at ON exchanges(started_at);
";

/// Serialize headers to a JSON object keyed by lowercased name. Duplicate header
/// names collapse (last value wins) — acceptable for the queryable capture this
/// change delivers.
// ponytail: object-keyed-by-name loses duplicate headers (e.g. Set-Cookie). Fine
// for query-by-header presence; switch to an array of pairs if per-value fidelity
// on duplicates ever matters.
fn headers_to_json(headers: &[(String, String)]) -> serde_json::Result<String> {
    let map: serde_json::Map<String, serde_json::Value> = headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), serde_json::Value::String(v.clone())))
        .collect();
    serde_json::to_string(&map)
}

/// Serialize the auto-flags to a JSON array of their stable string labels.
fn flags_to_json(flags: &[Flag]) -> serde_json::Result<String> {
    let labels: Vec<&str> = flags.iter().map(|f| f.label()).collect();
    serde_json::to_string(&labels)
}

/// Reconstruct the auto-flags from a stored JSON array of labels; unknown labels
/// (e.g. from a newer writer) are skipped rather than failing the whole row.
fn flags_from_json(text: &str) -> Result<Vec<Flag>> {
    let labels: Vec<String> = serde_json::from_str(text).map_err(store_err)?;
    Ok(labels.iter().filter_map(|l| Flag::from_label(l)).collect())
}

/// Reconstruct the header pairs from a stored JSON object.
fn headers_from_json(text: &str) -> Result<Vec<(String, String)>> {
    let map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(text).map_err(store_err)?;
    Ok(map
        .into_iter()
        .map(|(k, v)| (k, v.as_str().unwrap_or_default().to_string()))
        .collect())
}

/// Bound the query limit: a missing or non-positive limit falls back to the default
/// (SQLite reads a negative `LIMIT` as "no limit"), a positive one is honored.
fn resolve_limit(limit: Option<i64>) -> i64 {
    match limit {
        Some(l) if l > 0 => l,
        _ => DEFAULT_QUERY_LIMIT,
    }
}

/// Map one row of the query projection into a [`StoredExchange`].
fn row_to_exchange(row: &sqlx::sqlite::SqliteRow) -> Result<StoredExchange> {
    let id: i64 = row.try_get("id").map_err(store_err)?;
    let params_text: String = row.try_get("params_json").map_err(store_err)?;
    let params: Vec<String> = serde_json::from_str(&params_text).map_err(store_err)?;
    let status: i64 = row.try_get("status").map_err(store_err)?;

    let exchange = CapturedExchange {
        method: row.try_get("method").map_err(store_err)?,
        url: row.try_get("url").map_err(store_err)?,
        host: row.try_get("host").map_err(store_err)?,
        endpoint: row.try_get("endpoint").map_err(store_err)?,
        query: row.try_get("query").map_err(store_err)?,
        params,
        req_headers: headers_from_json(
            &row.try_get::<String, _>("req_headers_json")
                .map_err(store_err)?,
        )?,
        req_body: row
            .try_get::<Option<Vec<u8>>, _>("req_body")
            .map_err(store_err)?
            .unwrap_or_default(),
        req_body_truncated: row.try_get("req_body_truncated").map_err(store_err)?,
        status: u16::try_from(status).unwrap_or(0),
        resp_headers: headers_from_json(
            &row.try_get::<String, _>("resp_headers_json")
                .map_err(store_err)?,
        )?,
        resp_body: row
            .try_get::<Option<Vec<u8>>, _>("resp_body")
            .map_err(store_err)?
            .unwrap_or_default(),
        resp_body_truncated: row.try_get("resp_body_truncated").map_err(store_err)?,
        started_at: row.try_get("started_at").map_err(store_err)?,
        duration_ms: row.try_get("duration_ms").map_err(store_err)?,
    };
    let flags = flags_from_json(&row.try_get::<String, _>("flags_json").map_err(store_err)?)?;
    let score: i64 = row.try_get("score").map_err(store_err)?;
    Ok(StoredExchange {
        id,
        exchange,
        flags,
        score,
    })
}

/// Restrict `path` to owner-only access on Unix (a no-op elsewhere). Used to keep
/// the traffic store — which holds captured credentials — unreadable by other users.
async fn restrict_to_owner(path: impl AsRef<Path>, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path.as_ref(), std::fs::Permissions::from_mode(mode)).await?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

/// Wrap any error from the store layer as an [`Error::Store`].
fn store_err<E: std::fmt::Display>(e: E) -> Error {
    Error::Store(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal exchange for store tests (empty bodies, now, 1ms).
    fn sample(
        endpoint: &str,
        status: u16,
        params: &[&str],
        headers: &[(&str, &str)],
    ) -> CapturedExchange {
        CapturedExchange {
            method: "GET".into(),
            url: format!("https://api.test{endpoint}"),
            host: "api.test".into(),
            endpoint: endpoint.into(),
            query: None,
            params: params.iter().map(|p| p.to_string()).collect(),
            req_headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            req_body: Vec::new(),
            req_body_truncated: false,
            status,
            resp_headers: vec![("content-type".into(), "application/json".into())],
            resp_body: b"{}".to_vec(),
            resp_body_truncated: false,
            started_at: Utc::now(),
            duration_ms: 1,
        }
    }

    #[tokio::test]
    async fn records_and_queries_by_every_dimension() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("traffic.db");
        let store = TrafficStore::open(&path).await.unwrap();

        let before = Utc::now() - chrono::Duration::seconds(1);
        store
            .record(&sample(
                "/api/users",
                200,
                &["id", "page"],
                &[("Authorization", "Bearer x")],
            ))
            .await
            .unwrap();
        store
            .record(&sample(
                "/api/orders",
                404,
                &["q"],
                &[("X-Trace-Id", "abc")],
            ))
            .await
            .unwrap();

        // endpoint
        assert_eq!(
            store
                .query(&TrafficQuery::new().by_endpoint("/api/users"))
                .await
                .unwrap()
                .len(),
            1
        );
        // status
        assert_eq!(
            store
                .query(&TrafficQuery::new().by_status(404))
                .await
                .unwrap()
                .len(),
            1
        );
        // host
        assert_eq!(
            store
                .query(&TrafficQuery::new().by_host("api.test"))
                .await
                .unwrap()
                .len(),
            2
        );
        // parameter (name presence)
        assert_eq!(
            store
                .query(&TrafficQuery::new().by_param("id"))
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            store
                .query(&TrafficQuery::new().by_param("missing"))
                .await
                .unwrap()
                .is_empty()
        );
        // header (case-insensitive name presence)
        assert_eq!(
            store
                .query(&TrafficQuery::new().by_header("authorization"))
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .query(&TrafficQuery::new().by_header("X-Trace-Id"))
                .await
                .unwrap()
                .len(),
            1
        );
        // time window
        assert_eq!(
            store
                .query(&TrafficQuery::new().from(before))
                .await
                .unwrap()
                .len(),
            2
        );
        let future = Utc::now() + chrono::Duration::seconds(3600);
        assert!(
            store
                .query(&TrafficQuery::new().from(future))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn captured_traffic_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("traffic.db");

        let store = TrafficStore::open(&path).await.unwrap();
        store
            .record(&sample("/keep", 201, &["a"], &[]))
            .await
            .unwrap();
        store.close().await;

        // Reopen the same file — previously captured exchanges are still there.
        let reopened = TrafficStore::open(&path).await.unwrap();
        let rows = reopened
            .query(&TrafficQuery::new().by_endpoint("/keep"))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].exchange.status, 201);
        assert_eq!(rows[0].exchange.method, "GET");
    }

    #[tokio::test]
    async fn capture_sink_never_blocks_when_store_is_behind() {
        let dir = tempfile::tempdir().unwrap();
        let store = TrafficStore::open(dir.path().join("traffic.db"))
            .await
            .unwrap();
        // Capacity 1: rapidly hand over more than fits. `capture` must return
        // immediately every time (dropping the overflow) — never awaiting the store.
        let sink = store.spawn_writer(1);
        for i in 0..50 {
            sink.capture(sample(&format!("/e{i}"), 200, &[], &[]));
        }
        // If capture had blocked, this test would hang rather than complete.
    }

    #[tokio::test]
    async fn analysis_is_persisted_queryable_and_ranks_the_triage_view() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("traffic.db");
        let store = TrafficStore::open(&path).await.unwrap();

        // An interesting exchange: auth token + numeric id param on an API path.
        store
            .record(&sample(
                "/api/users",
                200,
                &["id"],
                &[("Authorization", "Bearer secret")],
            ))
            .await
            .unwrap();
        // A plain static asset (non-JSON response set below) — no categories.
        let mut asset = sample("/static/app.js", 200, &[], &[]);
        asset.resp_headers = vec![("content-type".into(), "application/javascript".into())];
        store.record(&asset).await.unwrap();
        // A server error.
        store
            .record(&sample("/broken", 500, &[], &[]))
            .await
            .unwrap();

        // Reopen to prove flags/score survive a restart.
        store.close().await;
        let store = TrafficStore::open(&path).await.unwrap();

        // The interesting exchange is flagged in both categories and scores > 0.
        let hot = store
            .query(&TrafficQuery::new().by_endpoint("/api/users"))
            .await
            .unwrap();
        assert!(hot[0].flags.contains(&Flag::Auth));
        assert!(hot[0].flags.contains(&Flag::Idor));

        // The static asset carries no flags and scores zero.
        let cold = store
            .query(&TrafficQuery::new().by_endpoint("/static/app.js"))
            .await
            .unwrap();
        assert!(cold[0].flags.is_empty());
        assert_eq!(cold[0].score, 0);
        assert!(hot[0].score > cold[0].score);

        // The error response is flagged and queryable by flag.
        let errors = store
            .query(&TrafficQuery::new().by_flag(Flag::Error.label()))
            .await
            .unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].exchange.endpoint, "/broken");

        // The triage view surfaces the highest-interest exchange first.
        let triage = store
            .query(&TrafficQuery::new().interest_first())
            .await
            .unwrap();
        assert_eq!(triage[0].exchange.endpoint, "/api/users");
        assert_eq!(triage.last().unwrap().exchange.endpoint, "/static/app.js");
    }

    /// The DB (captured credentials) is owner-only, and its parent directory is too,
    /// so no other user can read the store or its `-wal`/`-shm` siblings.
    #[cfg(unix)]
    #[tokio::test]
    async fn store_and_parent_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("data");
        let path = parent.join("traffic.db");
        let _store = TrafficStore::open(&path).await.unwrap();

        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600, "DB file is owner-only");
        let dir_mode = std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "store directory is owner-only");
    }
}
