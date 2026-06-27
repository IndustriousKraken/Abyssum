-- Annotations schema (d00-add-annotations).
--
-- Freeform notes on sessions and findings, reusable color-coded tags, and the
-- session<->tag many-to-many join. Additive over 0001/0002/0003 and applied on
-- the same `connect` path as the rest of the schema.
--
-- Cascades (the foreign-key pragma is enabled on every connection, so these
-- fire automatically): deleting a session drops its notes and its tag
-- applications; deleting a finding drops the notes attached to that finding. The
-- shared `tags` rows are never removed by any cascade -- only the per-session
-- *application* of a tag is owned, the tag definition is global.

CREATE TABLE notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,                -- FK -> sessions.session_id
    finding_id INTEGER,                      -- optional FK -> findings.id (NULL = session-level note)
    content    TEXT NOT NULL,
    author     TEXT NOT NULL,                -- the username that wrote the note
    created_at TEXT NOT NULL,                -- RFC-3339, bound explicitly (sorts newest-first)
    edited_at  TEXT,                         -- set when the content is later edited
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (finding_id) REFERENCES findings(id)         ON DELETE CASCADE
);

CREATE INDEX idx_notes_session ON notes(session_id);
CREATE INDEX idx_notes_finding ON notes(finding_id);

CREATE TABLE tags (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,        -- normalized: trimmed + lower-cased (so case/space never duplicates)
    color       TEXT NOT NULL,               -- hex color, #RRGGBB
    description TEXT
);

CREATE TABLE session_tags (
    session_id TEXT NOT NULL,                -- FK -> sessions.session_id
    tag_id     INTEGER NOT NULL,             -- FK -> tags.id
    PRIMARY KEY (session_id, tag_id),        -- a tag applies to a session at most once
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id)     REFERENCES tags(id)             ON DELETE CASCADE
);

CREATE INDEX idx_session_tags_tag ON session_tags(tag_id);
