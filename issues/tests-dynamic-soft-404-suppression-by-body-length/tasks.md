# Tasks: dynamic soft-404 (body-length) suppression tests

All tests land in the existing `#[cfg(test)] mod tests` in
`abyssum-scanners/src/rest_discovery.rs`. Use the in-module helpers `observed`
(builds an `Observed` with the real fingerprint) and the pattern from
`soft_404_baseline` to build a `Baseline` from an `Observed`. Bodies must be
substantial: `bodies_similar` only applies when both **normalized** lengths are
at least `MIN_SIMILAR_BODY_LEN` (64) and within `BODY_LEN_TOLERANCE` (5%) of the
larger, so construct baseline/observed bodies whose whitespace-normalized lengths
land in those ranges (e.g. baseline ≈ 200 chars; "similar" ≈ within 10 chars;
"dissimilar" ≈ double the baseline).

- [ ] 1.1 `classifies_dynamic_soft_404_absent_by_body_length` — build a
  substantial baseline body (normalized length ≥ 64, e.g. a ~200-char not-found
  page) and a `Baseline` from it at status 200. Build an `observed(200, .., body)`
  whose body has **different text** (so a different `body_hash`) but a normalized
  length within 5% of the baseline (e.g. the same error page echoing a different
  path). Assert `classify(&resp, Some(&baseline)) == Classification::Absent` —
  this exercises the `bodies_similar` arm of `Baseline::matches`, distinct from
  the hash arm.
- [ ] 1.2 `classifies_distinct_long_body_not_absent_despite_same_status` — reuse
  the same substantial 200 baseline. Build an `observed(200, .., body)` with a
  different hash AND a normalized length well outside the 5% tolerance (e.g.
  roughly twice the baseline length). Assert `classify(&resp, Some(&baseline)) ==
  Classification::Accessible` (a genuine 200 distinct from the baseline) — proving
  length similarity, not status alone, is what suppresses a dynamic soft-404.
- [ ] 1.3 `baseline_matches_on_similar_length_with_differing_hash` — a direct
  `Baseline::matches` test: same status, `body_hash` differing from the observed,
  `body_len` within tolerance ⇒ `matches` returns `true`; and a sibling assertion
  where only the status differs (similar length, differing hash, different status)
  ⇒ `matches` returns `false`, confirming the status equality guard still holds.
- [ ] 1.4 `short_bodies_never_match_on_length_alone` — build a baseline and an
  observed at the same status whose normalized lengths are both **below** 64 and
  differ in content (differing hash) but happen to be equal/near-equal length.
  Assert `classify` does **not** return `Absent` (it classifies by status),
  confirming the `MIN_SIMILAR_BODY_LEN` guard prevents short coincidental
  length matches from being treated as soft-404s.
