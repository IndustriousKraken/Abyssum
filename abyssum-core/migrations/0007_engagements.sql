-- Engagements (h01-add-engagements).
--
-- An engagement is a named grouping an operator creates, under which scans are
-- organized and the job's scope / authorization documents are kept for reference.
-- Additive over 0001-0006 and applied on the same `connect` path as the rest of
-- the schema.
--
-- The authorized-operator set is a first-class table (`engagement_operators`),
-- not a single owner column, so a future collaboration change can widen the set
-- without a schema rewrite (see roadmap/engagement-collaboration.md). Today it
-- holds exactly the creator. Provenance — which operator added each item, and
-- when — is recorded from day one, since that is the one thing painful to
-- backfill later.
--
-- Cascade (the foreign-key pragma is enabled on every connection): deleting an
-- engagement drops its operator set and its documents; deleting a user drops the
-- engagements they own and their memberships. A scan outlives its engagement —
-- removing the engagement only clears the association (ON DELETE SET NULL).

CREATE TABLE engagements (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_user_id INTEGER NOT NULL,               -- creator; the initial sole authorized operator
    name          TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- The per-engagement authorized-operator set (the collaboration seam). Today it
-- contains exactly the creator; widening it later is an INSERT, not a redesign.
CREATE TABLE engagement_operators (
    engagement_id INTEGER NOT NULL,
    user_id       INTEGER NOT NULL,
    added_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (engagement_id, user_id),
    FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)       REFERENCES users(id)       ON DELETE CASCADE
);

-- Scope / authorization documents. A document is pasted text, an external URL, or
-- an uploaded file; the payload lives in `content` (text/url) or `blob` (file).
-- Operator-supplied file bytes are untrusted: the served `content_type` is the
-- one the engine detected from the bytes, never the client's claim.
CREATE TABLE engagement_documents (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id    INTEGER NOT NULL,
    kind             TEXT NOT NULL,                -- 'text' | 'url' | 'file'
    content          TEXT,                         -- pasted text or the URL (NULL for a file)
    blob             BLOB,                         -- uploaded file bytes (NULL for text/url)
    content_type     TEXT,                         -- detected served content type (file only)
    filename         TEXT,                         -- sanitized original filename (file only)
    added_by_user_id INTEGER NOT NULL,             -- provenance: who attached it
    added_at         TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (engagement_id)    REFERENCES engagements(id) ON DELETE CASCADE,
    FOREIGN KEY (added_by_user_id) REFERENCES users(id)
);

CREATE INDEX idx_engagements_owner         ON engagements(owner_user_id);
CREATE INDEX idx_engagement_operators_user ON engagement_operators(user_id);
CREATE INDEX idx_engagement_documents_eng  ON engagement_documents(engagement_id);

-- Nullable engagement association on scan sessions, plus which operator made it.
-- A session with no engagement is valid and behaves exactly as before. "At most
-- one engagement per scan" is structural: a single column, so a reassignment
-- replaces rather than accumulates. The association is written after creation and
-- never touched by save_session's upsert, so a re-save cannot clear it.
ALTER TABLE sessions ADD COLUMN engagement_id INTEGER
    REFERENCES engagements(id) ON DELETE SET NULL;
ALTER TABLE sessions ADD COLUMN engagement_assigned_by INTEGER
    REFERENCES users(id);

CREATE INDEX idx_sessions_engagement ON sessions(engagement_id);
