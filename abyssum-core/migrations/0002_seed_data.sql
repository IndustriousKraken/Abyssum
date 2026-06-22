-- Reference-data store (a04-add-seed-data).
--
-- Curated wordlists and the User-Agent pool live in the database so they are
-- queryable and extensible at runtime, while still shipping embedded in the
-- binary and seeded on first run. Seeding is idempotent, keyed by the natural
-- identity captured in the UNIQUE constraints below (list name + value; UA
-- value), so re-running tops up only the missing rows -- there is no
-- content-hash or version check. This file is additive over 0001 and is applied
-- on the same `connect` path as the persistence schema.

CREATE TABLE wordlists (
    name TEXT PRIMARY KEY              -- e.g. 'rest_endpoints', 'graphql_queries'
);

CREATE TABLE wordlist_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    list_name   TEXT NOT NULL,         -- FK -> wordlists.name
    value       TEXT NOT NULL,         -- the path / query body
    label       TEXT,                  -- entry label (e.g. a GraphQL query name); NULL for plain lists
    position    INTEGER NOT NULL,      -- preserves seeded order
    UNIQUE(list_name, value),          -- natural identity -> idempotent re-seed
    FOREIGN KEY (list_name) REFERENCES wordlists(name) ON DELETE CASCADE
);

-- Lookups fetch one list ordered by position; this index serves both clauses.
CREATE INDEX idx_wordlist_entries_list ON wordlist_entries(list_name, position);

CREATE TABLE user_agents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    value       TEXT UNIQUE NOT NULL,  -- the literal User-Agent header value
    category    TEXT,                  -- e.g. browser, mobile, bot, security
    realistic   BOOLEAN NOT NULL       -- the default rotation pool is realistic = 1
);

-- The default rotation pool selects on `realistic`; index it.
CREATE INDEX idx_user_agents_realistic ON user_agents(realistic);
