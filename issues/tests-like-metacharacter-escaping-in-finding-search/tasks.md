# Tasks: LIKE-metacharacter escaping tests for free-text finding search

All tests land in `abyssum-core/tests/persistence.rs` and reuse the existing
helpers (`open_temp`, `session_record`, `finding`, `ts`, `titles`). Each test
seeds one session with a small fixture of findings whose titles contain (or do
not contain) a SQL `LIKE` metacharacter literally, then queries with
`FindingFilter::new().session(id).query(...)` and asserts the result set is
exactly the literal matches. The contrast row (a title that a *wildcard*
interpretation would wrongly match) is what proves escaping is in effect.

- [ ] 1.1 `free_text_query_matches_percent_literally` — seed findings titled
  `"50% off coupon"` and `"plain discount"`. Query `"50%"`. Assert the result is
  exactly `["50% off coupon"]`. (Without escaping, `%` is a wildcard and the
  `%50%%` pattern would still match only this row here, so ALSO add the
  all-rows guard:) additionally query `"%"` alone and assert it returns **only**
  findings whose title contains a literal `%` (here just `"50% off coupon"`),
  **not** every seeded finding.
- [ ] 1.2 `free_text_query_matches_underscore_literally` — seed findings titled
  `"user_id leak"` and `"userXid mismatch"`. Query `"user_id"`. Assert the
  result is exactly `["user_id leak"]`. Without escaping, `_` matches any single
  character and `"userXid mismatch"` would also be returned — so the test fails
  if escaping regresses.
- [ ] 1.3 `free_text_query_matches_backslash_literally` — seed findings titled
  `"path C:\\temp leak"` (a single literal backslash) and `"path C:/tmp note"`.
  Query `"C:\\temp"` (one literal backslash). Assert the result is exactly the
  backslash-bearing finding, confirming the escape character itself is treated
  literally and the `ESCAPE '\'` clause does not corrupt the match.
- [ ] 1.4 `free_text_query_metacharacters_still_case_insensitive` — seed a
  finding titled `"Cache 50% HIT"`, query `"50% hit"` (lower case), and assert it
  is returned — confirming metacharacter escaping composes with the existing
  case-insensitive `LIKE` behavior rather than replacing it.
