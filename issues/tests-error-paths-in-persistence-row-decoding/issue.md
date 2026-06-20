# tests-error-paths-in-persistence-row-decoding

## Coverage gap

The persistence read path reconstructs rows through several fallible decoders,
each of which has an `Err(Error::Persistence(_))` arm for a stored value that
does not conform to the schema's documented vocabulary. **None of those error
arms are exercised by any test.** Every persistence test
(`abyssum-core/tests/persistence.rs`) writes through the typed API and reads it
back, so only conforming data ever reaches the decoders; a corrupt, foreign, or
hand-tampered row is never read back.

The untested decoders, all reached from `get_session` / `list_sessions` /
`get_session_with_findings` / `findings_for_session`:

- `abyssum-core/src/persistence/records.rs:222` — `session_status_from_str`
  returns `Err(Error::Persistence)` for an unknown session-status token
  (`other => ...`).
- `abyssum-core/src/persistence/records.rs:247` — `status_from_str` returns
  `Err(Error::Persistence)` for an unknown finding-status token.
- `abyssum-core/src/persistence/records.rs:272` — `severity_from_str` returns
  `Err(Error::Persistence)` for an unknown severity token.
- `abyssum-core/src/persistence/db.rs:470` — `parse_uuid` returns
  `Err(Error::Persistence)` for an unparseable stored uuid (reached by
  `row_to_session` via `list_sessions`, and by `row_to_finding`).
- `abyssum-core/src/persistence/db.rs:464` — `from_json` returns
  `Err(Error::Persistence)` for a malformed serialized field (`targets_json`,
  `scanners_json`, `target_json`, `evidence_json`).

These are reachable in practice: the `0001_init.sql` schema stores `status`,
`severity`, `session_id`, and the JSON blobs as plain `TEXT` with **no `CHECK`
constraint** (`abyssum-core/migrations/0001_init.sql:14-44`), so a raw insert of
a non-conforming value succeeds and the fault only surfaces on read. The
contract is that the read surfaces it as a clean `Error::Persistence` (the
variant documented for storage/query failures at
`abyssum-core/src/error.rs:52`), **not** a panic or a silently wrong value.

## Source location

- `abyssum-core/src/persistence/db.rs` — `row_to_session` (393), `row_to_finding`
  (422), `parse_uuid` (470), `from_json` (464).
- `abyssum-core/src/persistence/records.rs` — `session_status_from_str` (222),
  `status_from_str` (247), `severity_from_str` (272).
- Tests land in `abyssum-core/tests/persistence.rs`.

## Acceptance criteria (against the existing specification)

This asserts already-implemented behavior; it introduces **no** new or changed
contract. The decoders already return `Error::Persistence` for non-conforming
stored values — these tests pin that.

Grounded in `openspec/specs/result-persistence/spec.md`:

- **Requirement: Durable Finding Storage** — "The stored status SHALL be one of
  the shared status values and the stored severity SHALL be one of the shared
  severity levels." A stored value outside those sets is a persistence fault; the
  read path SHALL surface it as `Error::Persistence`, not panic or return a wrong
  value.
- **Requirement: Durable Scan Session Storage** and **Requirement: Query
  Sessions** — session retrieval (`get_session`, `list_sessions`,
  `get_session_with_findings`) returns a `Result`; a corrupt row makes that
  result an `Err(Error::Persistence)`.
- Error model: `abyssum-core/src/error.rs:52` documents `Error::Persistence` as
  the variant for a failed storage/query operation.

Acceptance: with the temp-file store from the existing `temp_db_path` / `open`
helpers, inserting a row carrying a non-conforming stored value via a raw `sqlx`
statement and then reading it back through the public API returns
`Err(Error::Persistence(_))` (never a panic, never `Ok`).
