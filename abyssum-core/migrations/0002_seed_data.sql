-- Seed-data (reference-data) schema (a04).
--
-- Curated reference data — per-scanner wordlists and the User-Agent pool — lives
-- in the database (queryable, extensible at runtime) rather than as compiled-in
-- constants, while still shipping inside the single self-contained binary: the
-- assets are embedded in the binary and copied into these tables on first run.
--
-- Idempotent seeding keys on natural identity (UNIQUE constraints below), so a
-- re-seed tops up only the missing rows and never duplicates. Order is preserved
-- explicitly by `position`, independent of insertion order, so a partial top-up
-- still lands each entry at its bundled position.

CREATE TABLE wordlists (
    name        TEXT PRIMARY KEY             -- e.g. 'rest_endpoints', 'graphql_queries'
);

CREATE TABLE wordlist_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    list_name   TEXT NOT NULL,               -- -> wordlists.name
    value       TEXT NOT NULL,               -- the path / query body
    label       TEXT,                        -- entry label, e.g. a GraphQL query name; NULL for plain lists
    position    INTEGER NOT NULL,            -- preserves seeded order
    UNIQUE(list_name, value)                 -- natural identity -> idempotent re-seed
);

CREATE TABLE user_agents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    value       TEXT UNIQUE NOT NULL,        -- natural identity -> idempotent re-seed
    category    TEXT,                        -- e.g. browser, mobile, bot, security
    realistic   BOOLEAN NOT NULL             -- default rotation pool is realistic = 1
);

-- Ordered, per-list lookup is the hot path (a scanner asks for one list by name).
CREATE INDEX idx_wordlist_entries_list ON wordlist_entries(list_name, position);
-- The default rotation pool filters on `realistic`.
CREATE INDEX idx_user_agents_realistic ON user_agents(realistic);
