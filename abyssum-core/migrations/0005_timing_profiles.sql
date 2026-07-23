-- Timing-profiles schema (g05-add-timing-profiles).
--
-- Reusable, per-user pacing shapes: a name plus a serialized PacingPolicy (the
-- delay distribution the rate limiter draws from). Owned by a user and private to
-- them, seeded from the built-in library on first use and extendable. Additive
-- over 0001-0004 and applied on the same `connect` path as the rest of the schema.
--
-- Cascade: deleting a user drops their timing profiles (the foreign-key pragma is
-- enabled on every connection).

CREATE TABLE timing_profiles (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_user_id INTEGER NOT NULL,               -- FK -> users.id (owner; private to them)
    name          TEXT NOT NULL,                  -- human-facing, unique within the owner's set
    policy_json   TEXT NOT NULL,                  -- serialized PacingPolicy (shape + window)
    built_in      INTEGER NOT NULL DEFAULT 0,     -- 1 = seeded from the built-in library
    UNIQUE(owner_user_id, name),                  -- a name is unique per owner (re-seed is a no-op)
    FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_timing_profiles_owner ON timing_profiles(owner_user_id);
