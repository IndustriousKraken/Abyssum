# Tasks

## 1. Storage component skeleton
- [x] 1.1 Add a `persistence` module in `abyssum-core` exposing a `DatabaseManager` that owns one connection pool
- [x] 1.2 Resolve the database file path from `database.path` in config; create its parent directory if missing
- [x] 1.3 Open the pool on startup and surface connection failures as a persistence error

## 2. Schema and migrations
- [x] 2.1 Add a `migrations/` directory with the initial migration creating the `sessions` and `findings` tables and their indexes
- [x] 2.2 Run pending migrations on startup before any query is served
- [x] 2.3 Ensure re-running migrations on an already-current store is a no-op

## 3. Session persistence
- [x] 3.1 Implement create/update of a session by `session_id` (upsert): identity, status, targets, scanner ids, timing, request/error counts
- [x] 3.2 Implement fetch of a single session by `session_id` returning its stored fields and status
- [x] 3.3 Implement list of sessions ordered newest-first with limit/offset paging

## 4. Finding persistence
- [x] 4.1 Implement save of a finding under a `session_id`, assigning a public `finding_id` (uuid) and retaining scanner id, target, status, severity, title, description, recommendations, and evidence
- [x] 4.2 Implement fetch of all findings for a session ordered by timestamp; expose each finding's stable `finding_id`
- [x] 4.3 Serialize/deserialize evidence and target fields round-trip without loss

## 5. Query and filter
- [x] 5.1 Implement finding search filterable by status, severity, scanner id, target, and free-text title/description
- [x] 5.2 Add a date-range filter (from/to over the finding timestamp) composable with the other filters
- [x] 5.3 Apply a result limit and stable ordering (newest-first) to search output
- [x] 5.4 Implement summary counts (sessions, findings, findings-by-severity), restrictable to a supplied subset of session ids

## 6. Deletion
- [x] 6.1 Implement transactional delete of a session and all its findings; report whether a session was removed

## 7. Tests (local only — no real targets)
- [x] 7.1 Restart-survival test: write a session + findings to a temp file, reopen the pool, assert all fields read back unchanged
- [x] 7.2 Finding-field-integrity test: assert a re-read finding keeps its `finding_id`, scanner id, target, status, severity, title, description, recommendations, and evidence
- [x] 7.3 Filter tests: status, scanner id, target, free-text, and date-range filters each return exactly the seeded matches, including combined filters
- [x] 7.4 Migration idempotency test: applying migrations twice on a temp store is a no-op and leaves the schema present
- [x] 7.5 Deletion test: deleting a session removes it and all its findings and leaves other sessions untouched
