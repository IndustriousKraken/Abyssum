-- Initial result-persistence schema (a03-add-result-persistence).
--
-- Two tables: `sessions` holds one row per scan run; `findings` holds many rows
-- per session, linked by the public `session_id`. Datetime columns use TEXT
-- affinity so the RFC-3339 strings sqlx writes for `DateTime<Utc>` are stored and
-- read back verbatim (NUMERIC affinity would try to coerce them). Later changes
-- (auth's owner column, annotations' notes) extend this additively via their own
-- migration files rather than editing this one.

CREATE TABLE sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL UNIQUE,        -- public uuid (ScanSession.id)
    status          TEXT NOT NULL,               -- pending|running|completed|cancelled|errored
    targets_json    TEXT NOT NULL,               -- serialized Vec<Target>
    scanners_json   TEXT NOT NULL,               -- serialized Vec<String> scanner ids
    error_count     INTEGER NOT NULL DEFAULT 0,  -- per-target scanner errors counted during the run
    completed_units INTEGER NOT NULL DEFAULT 0,  -- scanner-target units completed
    total_units     INTEGER NOT NULL DEFAULT 0,  -- scanner-target units planned
    started_at      TEXT,                         -- when the run started (NULL while pending)
    finished_at     TEXT,                         -- when the run reached a terminal state
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sessions_status     ON sessions(status);
CREATE INDEX idx_sessions_created_at ON sessions(created_at);

CREATE TABLE findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,  -- stable Finding.id assigned on save
    session_id      TEXT NOT NULL,               -- FK -> sessions.session_id
    scanner_id      TEXT NOT NULL,               -- stable scanner id, e.g. rest_discovery
    status          TEXT NOT NULL,               -- vulnerable|safe|info
    severity        TEXT NOT NULL,               -- info|low|medium|high|critical
    title           TEXT NOT NULL,
    description     TEXT,
    recommendations TEXT,                         -- remediation guidance
    target_json     TEXT NOT NULL,               -- full serialized Target (lossless round-trip)
    target_full_url TEXT NOT NULL,               -- denormalized Target::full_url for indexed filtering
    evidence_json   TEXT,                         -- serialized structured evidence
    timestamp       TEXT NOT NULL,               -- when the finding was produced
    created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_findings_session_id ON findings(session_id);
CREATE INDEX idx_findings_scanner_id ON findings(scanner_id);
CREATE INDEX idx_findings_status     ON findings(status);
CREATE INDEX idx_findings_severity   ON findings(severity);
CREATE INDEX idx_findings_target     ON findings(target_full_url);
CREATE INDEX idx_findings_timestamp  ON findings(timestamp);
