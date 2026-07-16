# Add scan-run diffing

## Why

A target changes over time — an endpoint that was `403` starts returning `200`, a debug
route appears, a CORS policy tightens. For repeat and unattended scanning, the useful
output is not the full finding list each time but *what changed since last run*. Scan
sessions are already persisted; comparing two of them turns a re-scan into a short
delta an operator can act on.

## What Changes

- Add a CLI `diff` command that takes two stored scan sessions and reports, for the
  same target(s): findings present in the newer run but not the older (added), present
  in the older but not the newer (resolved), and findings whose severity or status
  changed between them.
- Unchanged findings are not listed individually (optionally summarized as a count).

This reads existing persisted sessions and their findings; it adds no scanning
behavior.
