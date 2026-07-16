# Add finding de-duplication and ranking

## Why

Low false-positive, high-signal output is existential for unattended and long-running
scans: a week-long run must surface the handful of things worth looking at, not ten
thousand rows. Today findings are reported as produced — duplicates repeat, and order
does not reflect importance. Collapsing duplicates and ranking by importance turns raw
output into a triage list.

## What Changes

- Collapse findings that describe the same issue (same scanner, same normalized
  target/endpoint, same finding class) into a single reported finding carrying an
  occurrence count.
- Order reported findings by importance — vulnerable status first, then higher
  severity, with informational findings grouped last — deterministically, so equal-rank
  findings keep a stable order.

This operates on findings already produced and persisted; it changes how they are
consolidated and ordered for reporting, not how they are detected.
