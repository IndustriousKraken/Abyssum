-- Authentication schema (c02-add-authentication).
--
-- Local accounts with Argon2id-hashed passwords, opaque server-side login
-- sessions, and an owner stamp on scan sessions. Additive over 0001/0002 and
-- applied on the same `connect` path as the persistence schema.
--
-- The login-session table is named `auth_sessions`, deliberately distinct from
-- the scan-run `sessions` table (a03) -- a logged-in user vs. a scan run are
-- different concepts and must not collide.

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,        -- natural identity; UNIQUE rejects duplicates
    password_hash TEXT NOT NULL,               -- Argon2id PHC string (salt + params embedded)
    role          TEXT NOT NULL,               -- admin|user (first registrant is admin)
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE auth_sessions (
    token        TEXT PRIMARY KEY,             -- opaque high-entropy CSPRNG token (the lookup key)
    user_id      INTEGER NOT NULL,             -- FK -> users.id
    created_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at   TEXT NOT NULL,                -- absolute hard ceiling on the session's age
    last_seen_at TEXT NOT NULL,                -- refreshed on each authorized use (idle timeout)
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_auth_sessions_user    ON auth_sessions(user_id);
CREATE INDEX idx_auth_sessions_expires ON auth_sessions(expires_at);

-- Ownership stamp on scan sessions. Nullable: web-surface sessions record the
-- creating user; CLI-initiated sessions have no owner. Written once at creation
-- and never updated (see persistence::save_session), so the owner is immutable.
ALTER TABLE sessions ADD COLUMN owner_user_id INTEGER REFERENCES users(id);

CREATE INDEX idx_sessions_owner ON sessions(owner_user_id);
