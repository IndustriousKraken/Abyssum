-- Per-user custom wordlists (g07-add-user-wordlist-upload).
--
-- Operator-provided wordlists imported through the web UI (paste or .txt upload),
-- owned by and private to the importing user, selectable per scan. Deliberately
-- DISTINCT from the seeded reference lists (`wordlists` / `wordlist_entries` from
-- 0001/0002): re-seeding the built-in lists on every `connect` only ever touches
-- those tables, so a user's imported lists are never overwritten or removed by a
-- re-seed. Additive over 0001-0005 and applied on the same `connect` path.
--
-- Cascade (the foreign-key pragma is enabled on every connection): deleting a
-- user drops their wordlists, and deleting a wordlist drops its entries.

CREATE TABLE user_wordlists (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_user_id INTEGER NOT NULL,               -- FK -> users.id (owner; private to them)
    name          TEXT NOT NULL,                  -- human-facing, unique within the owner's set
    created_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(owner_user_id, name),                  -- a name is unique per owner
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE user_wordlist_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    wordlist_id INTEGER NOT NULL,                 -- FK -> user_wordlists.id
    value       TEXT NOT NULL,                    -- a normalized entry (trimmed, lowercased)
    position    INTEGER NOT NULL,                 -- import order, so a lookup is deterministic
    FOREIGN KEY (wordlist_id) REFERENCES user_wordlists(id) ON DELETE CASCADE
);

CREATE INDEX idx_user_wordlists_owner        ON user_wordlists(owner_user_id);
CREATE INDEX idx_user_wordlist_entries_list  ON user_wordlist_entries(wordlist_id);
