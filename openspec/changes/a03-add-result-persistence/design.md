# Design: Result Persistence

## Technical Approach

Persistence lives in `abyssum-core` as a `DatabaseManager`-style component owning a single
connection pool. It exposes async methods to create/update sessions, save findings, and
query both. Orchestration and the surfaces call it; scanners never touch it directly (they
return findings up to the engine, which persists them).

The store is **SQLite** accessed through **`sqlx`** with its async SQLite driver, sharing
the `tokio` runtime from bootstrap. A pooled connection (`sqlx::SqlitePool`) is created once
and cloned cheaply where needed. The database file path comes from the bootstrap config
(`database.path`); the parent directory is created on startup if absent.

## Library Choices

- **DB / driver:** `sqlx` with the `runtime-tokio` + `sqlite` features. Queries are plain
  SQL; no ORM. We prefer `sqlx`'s compile-time-unchecked `query`/`query_as` for portability
  (no build-time DB) and map rows into domain structs by hand.
- **Migrations:** `sqlx::migrate!` driven by versioned SQL files under a `migrations/`
  directory, applied idempotently on startup via the `_sqlx_migrations` tracking table. This
  replaces v1's `CREATE TABLE IF NOT EXISTS` ad-hoc approach so the schema can evolve.
- **Serialization of complex fields:** `serde_json` for the columns that hold structured
  data (the target list, scanner-id list, finding evidence). Scalars stay as native columns
  so they remain filterable.
- **IDs / time:** `uuid` for the public session id; `chrono` (`DateTime<Utc>`) for
  timestamps, stored as ISO-8601 / SQLite `TIMESTAMP`.

## Schema Sketch

Two tables. `sessions` holds one row per scan run; `findings` holds many rows per session,
linked by the public `session_id`. Denormalized target columns on `findings` keep
target-based filtering a simple indexed comparison.

```sql
CREATE TABLE sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT UNIQUE NOT NULL,        -- public uuid
    status          TEXT NOT NULL,               -- pending|running|completed|cancelled|errored (matches SessionStatus)
    targets_json    TEXT NOT NULL,               -- serialized target list
    scanners_json   TEXT NOT NULL,               -- serialized scanner-id list
    start_time      TIMESTAMP,
    end_time        TIMESTAMP,
    total_requests  INTEGER NOT NULL DEFAULT 0,
    error_count     INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      TEXT UNIQUE NOT NULL,        -- public stable id (uuid); annotations (d00) reference this
    session_id      TEXT NOT NULL,               -- FK -> sessions.session_id
    scanner_id      TEXT NOT NULL,               -- stable scanner id, e.g. rest_discovery
    status          TEXT NOT NULL,               -- Status: vulnerable|safe|info
    severity        TEXT NOT NULL,               -- Severity: info|low|medium|high|critical
    title           TEXT NOT NULL,
    description     TEXT,
    recommendations TEXT,                        -- remediation guidance (Finding.recommendations)
    target_url      TEXT NOT NULL,
    target_full_url TEXT NOT NULL,
    evidence_json   TEXT,                        -- serialized evidence
    timestamp       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sessions_status      ON sessions(status);
CREATE INDEX idx_sessions_created_at  ON sessions(created_at);
CREATE INDEX idx_findings_session_id  ON findings(session_id);
CREATE INDEX idx_findings_scanner_id  ON findings(scanner_id);
CREATE INDEX idx_findings_status      ON findings(status);
CREATE INDEX idx_findings_target      ON findings(target_full_url);
CREATE INDEX idx_findings_timestamp   ON findings(timestamp);
```

## Architecture Decisions

### Decision: Migrations over `CREATE TABLE IF NOT EXISTS`
v1 created tables ad hoc, which makes schema evolution silent and fragile. Versioned
migrations record what has been applied and let later changes (auth adds an owner column,
annotations adds notes) extend the schema additively via their own migration files.

### Decision: No ownership column here
The `authentication` change owns user/ownership and will add an `owner` column to `sessions`
via its own migration plus a `MODIFIED` requirement. This capability stays ownership-blind so
the two changes don't collide.

### Decision: Denormalize target onto findings
Filtering findings by target is a primary query. Storing `target_full_url` directly on each
finding (indexed) avoids a join through the session's serialized target list.

### Decision: Atomic session deletion
Deleting a session and its findings runs in one transaction so a crash can't leave orphaned
findings or a half-deleted session.

### Decision: Re-saving a session is idempotent (upsert)
Orchestration updates a session as it progresses (pending → running → completed). Persisting
the same `session_id` again updates the existing row rather than inserting a duplicate.

## Testing

- Round-trip tests against a temporary on-disk SQLite file (created in a temp dir): write a
  session + findings, drop the pool, reopen the file, assert the data reads back unchanged —
  proving restart survival.
- Filter tests: seed findings spanning multiple statuses, scanner ids, targets, and
  timestamps, then assert each filter (status, scanner, target, date range, free-text) and
  combinations return exactly the expected rows.
- A migration test: apply migrations to an empty file, then apply again, and assert it is a
  no-op (idempotent) and the schema is present.
- Deletion test: delete a session and assert both it and all its findings are gone.
- All tests are local; no network, no real targets.
