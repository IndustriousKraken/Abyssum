# Tasks: error-path tests for persistence row decoding

All tests land in `abyssum-core/tests/persistence.rs` and use the existing
helpers (`temp_db_path`, `DatabaseManager::open`, `db.pool()`). Bring
`abyssum_core::Error` into scope in the test module. Each test inserts one
non-conforming row with a raw `sqlx::query(...)` against `db.pool()` (the schema
has no `CHECK` constraints, so the insert succeeds), then reads it back through
the public API and asserts `Err(Error::Persistence(_))`. A valid parent
`sessions` row (via `upsert_session`) is created first for the finding tests so
the only fault is the field under test.

## 1. Session decoder error paths

- [ ] 1.1 `get_session_errors_on_unknown_stored_status` — insert a `sessions`
  row (fill every `NOT NULL` column: `session_id` = a valid uuid string,
  `status` = `"bogus"`, `targets_json` = `"[]"`, `scanners_json` = `"[]"`,
  `created_at` / `updated_at` = an RFC3339 timestamp) via raw `sqlx`, then assert
  `db.get_session(that_uuid).await` returns `Err(Error::Persistence(_))`
  (exercises `session_status_from_str`, records.rs:222).
- [ ] 1.2 `list_sessions_errors_on_invalid_stored_uuid` — insert a `sessions`
  row with `session_id` = `"not-a-uuid"` (otherwise valid: `status` =
  `"completed"`, JSON columns `"[]"`, timestamps set), then assert
  `db.list_sessions(10, 0).await` returns `Err(Error::Persistence(_))`
  (exercises `parse_uuid` via `row_to_session`, db.rs:470). `list_sessions` is
  used here because `get_session` cannot be handed a non-uuid key.
- [ ] 1.3 `get_session_errors_on_malformed_targets_json` — insert a `sessions`
  row with a valid uuid and status but `targets_json` = `"{ not valid json"`,
  then assert `db.get_session(that_uuid).await` returns
  `Err(Error::Persistence(_))` (exercises `from_json`, db.rs:464).

## 2. Finding decoder error paths

- [ ] 2.1 `findings_for_session_errors_on_unknown_stored_status` — `upsert_session`
  a valid session, then raw-insert a `findings` row under it with `status` =
  `"broken"` (every other `NOT NULL` finding column filled with conforming
  values: `severity` = `"info"`, `target_json` = a serialized `Target`,
  `target_url` / `target_full_url` = a url string, `timestamp` / `created_at`
  set), then assert `db.findings_for_session(session_id).await` returns
  `Err(Error::Persistence(_))` (exercises `status_from_str`, records.rs:247).
- [ ] 2.2 `findings_for_session_errors_on_unknown_stored_severity` — as 2.1 but
  with a valid `status` = `"info"` and `severity` = `"extreme"`; assert the read
  returns `Err(Error::Persistence(_))` (exercises `severity_from_str`,
  records.rs:272).
- [ ] 2.3 `findings_for_session_errors_on_malformed_evidence_json` — as 2.1 but
  with valid `status` / `severity` and `evidence_json` = `"{ not json"`; assert
  the read returns `Err(Error::Persistence(_))` (exercises the `from_json` arm
  for `evidence`, db.rs:432-435 → 464).
- [ ] 2.4 `search_findings_errors_on_unknown_stored_severity` — reusing the row
  inserted as in 2.2, assert that `db.search_findings(&FindingFilter::new())`
  also returns `Err(Error::Persistence(_))`, confirming the search read path
  decodes through the same `row_to_finding` guard.
