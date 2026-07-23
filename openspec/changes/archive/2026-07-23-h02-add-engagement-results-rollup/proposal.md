# Engagement results rollup

## Why

`h01` organizes scans under an engagement and keeps its scope and authorization alongside them,
but the engagement view lists the scans without bringing their *results* together. An operator
running a job wants the engagement's findings in one place — a severity breakdown and the
findings across all its scans — without opening each scan session in turn.

## What Changes

- An engagement's detail view gains a **results rollup**: a breakdown of its findings by severity
  and the findings aggregated across all scans associated with the engagement.
- The rollup covers exactly that engagement's associated sessions and follows the same per-user
  visibility as the rest of the interface.

## Note

No new persistence. This reuses the existing `result-persistence` "Summary Counts" requirement,
which already allows counts to be *"restrictable to a supplied subset of sessions"* — the subset
here is the engagement's sessions, keeping the store ownership- and engagement-blind. Depends on
`h01-add-engagements` (engagements and their scan associations); ordered after it by the `h0x`
prefix. Nothing here touches `ScanContext::send`, pacing, or User-Agent rotation.
