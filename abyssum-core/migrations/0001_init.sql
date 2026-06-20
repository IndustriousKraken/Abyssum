-- Initial result-persistence schema (a03).
--
-- Two tables: `sessions` holds one row per scan run; `findings` holds many rows
-- per session, linked by the public `session_id`. Complex fields (the target
-- list, scanner-id list, finding evidence, and the canonical target) are stored
-- as serialized JSON so they round-trip without loss; scalars stay native so
-- they remain filterable. Denormalized target columns on `findings` keep
-- target-based filtering a simple indexed comparison.
--
-- Later changes extend this schema additively via their own migration files
-- (e.g. authentication adds an owner column; this capability stays
-- ownership-blind).

CREATE TABLE sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT UNIQUE NOT NULL,        -- public uuid
    status          TEXT NOT NULL,               -- pending|running|completed|cancelled|errored
    targets_json    TEXT NOT NULL,               -- serialized target list
    scanners_json   TEXT NOT NULL,               -- serialized scanner-id list
    start_time      TEXT,                        -- ISO-8601 (RFC3339)
    end_time        TEXT,
    total_requests  INTEGER NOT NULL DEFAULT 0,
    error_count     INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL
);

CREATE TABLE findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id      TEXT UNIQUE NOT NULL,        -- public stable uuid; annotations (d00) reference this
    session_id      TEXT NOT NULL,               -- -> sessions.session_id
    scanner_id      TEXT NOT NULL,               -- stable scanner id, e.g. rest_discovery
    status          TEXT NOT NULL,               -- vulnerable|safe|info
    severity        TEXT NOT NULL,               -- info|low|medium|high|critical
    title           TEXT NOT NULL,
    description     TEXT,
    recommendations TEXT,                        -- remediation guidance
    target_url      TEXT NOT NULL,               -- origin, denormalized for filtering
    target_full_url TEXT NOT NULL,               -- full request URL, denormalized for filtering
    target_json     TEXT NOT NULL,               -- canonical target, for lossless reconstruction
    evidence_json   TEXT,                        -- serialized evidence
    timestamp       TEXT NOT NULL,               -- ISO-8601 (RFC3339)
    created_at      TEXT NOT NULL
);

CREATE INDEX idx_sessions_status      ON sessions(status);
CREATE INDEX idx_sessions_created_at  ON sessions(created_at);
CREATE INDEX idx_findings_session_id  ON findings(session_id);
CREATE INDEX idx_findings_scanner_id  ON findings(scanner_id);
CREATE INDEX idx_findings_status      ON findings(status);
CREATE INDEX idx_findings_severity    ON findings(severity);
CREATE INDEX idx_findings_target      ON findings(target_full_url);
CREATE INDEX idx_findings_timestamp   ON findings(timestamp);
