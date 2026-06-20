# tests-dynamic-soft-404-suppression-by-body-length

## Coverage gap

The REST discovery scanner suppresses two kinds of soft-404. `Baseline::matches`
(`abyssum-scanners/src/rest_discovery.rs:247`) treats a probed response as
indistinguishable from the not-found baseline when the status matches **and**
either the normalized-body hash matches (a *static* soft-404) **or** the body
lengths are similar (a *dynamic* soft-404 that echoes the path but is otherwise
the same error page):

```rust
self.status == observed.status
    && (self.body_hash == observed.body_hash
        || bodies_similar(self.body_len, observed.body_len))
```

The length-similarity arm — the dynamic soft-404 path — is never exercised
through `matches` / `classify`. Every classifier test that reaches `Absent` via
the baseline does so with an **identical** (or whitespace-equivalent) body, which
matches on the `body_hash ==` arm:

- `classifies_200_soft_404_as_absent` (rest_discovery.rs:488) — identical body.
- `classifies_200_soft_404_absent_even_with_reformatted_body`
  (rest_discovery.rs:496) — whitespace-normalized to the **same** hash.
- `hard_404_baseline_suppresses_matching_404s_only` (rest_discovery.rs:534) —
  identical body.

`bodies_similar` is unit-tested in isolation
(`bodies_similar_only_for_substantial_close_lengths`, rest_discovery.rs:684), but
the integration that actually performs dynamic-soft-404 suppression — same
status, **differing** hash, similar length → `Absent` — has no test, and neither
does its negative counterpart (same status, differing hash, **dissimilar** length
→ classified by status, not suppressed). A regression in the `||` arm of
`matches` would let dynamic soft-404 targets yield a finding for every path with
no test catching it.

## Source location

- `abyssum-scanners/src/rest_discovery.rs` — `Baseline::matches` (247-252),
  `bodies_similar` (428-435), `classify` (265-285).
- Tests land in the existing `#[cfg(test)] mod tests` in
  `abyssum-scanners/src/rest_discovery.rs` (helpers `observed` and
  `soft_404_baseline` already exist there).

## Acceptance criteria (against the existing specification)

This asserts already-implemented behavior; it introduces **no** new or changed
contract. The dynamic-soft-404 (length-similarity) suppression already exists —
these tests pin it.

Grounded in `openspec/specs/rest-discovery/spec.md`, **Requirement:
Wordlist-Based Endpoint Discovery**, scenario **Soft-404 is not a finding**:

> - **GIVEN** a target that returns a 2xx status with a not-found body for unknown paths
> - **WHEN** the scanner probes an unknown path
> - **THEN** it SHALL classify the path as absent
> - **AND** SHALL NOT report it as a discovered endpoint

A dynamic not-found page (same status, a body that differs only by echoing the
requested path but stays the same length class) is such a soft-404 and SHALL be
classified `Absent`. A genuinely different substantial body at the same status
(length well outside tolerance) SHALL NOT be suppressed by the baseline.

Acceptance: `classify` returns `Classification::Absent` for a same-status,
different-hash, similar-length response against a substantial baseline, and does
**not** return `Absent` (it classifies by status) when the same-status response
has a body length outside the similarity tolerance.
