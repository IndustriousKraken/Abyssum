## Why

Bug bounty hunters do their actual work *after* a scan finishes: they turn findings into a
submission. v1 had a `ReportGenerator` that rendered a session's findings as Markdown, JSON,
and CSV, plus a HackerOne-shaped export — that capability is load-bearing for the product's
value and must carry over to v2.

This change specifies report generation over the persisted scan record. It depends on
`result-persistence` for the stored sessions and findings (scanner id, target, status
classification, severity, evidence) that a report is built from; it adds no new scanning
behavior.

## What Changes

### 1. Markdown submission report

Render a single session's findings as a self-contained Markdown document suitable for a
bug-bounty submission: target and scan metadata, an executive summary with a severity
breakdown, and per-finding detail. Each finding includes its type, severity, target/endpoint,
description, evidence, and a remediation recommendation, grouped most-severe-first.

### 2. JSON export

Produce a structured JSON export of one or more sessions, each with its metadata and its full
list of findings (type, severity, target, status, evidence). The shape is stable and
machine-readable for downstream tooling.

### 3. CSV summary

Produce a flat CSV summary with one row per finding across the selected sessions, carrying the
columns an operator triages on: session, target, scanner id, finding type, severity, endpoint,
and a short description.

### 4. HackerOne-formatted export

Produce a single Markdown report shaped to HackerOne's submission template (Summary, Steps To
Reproduce, Impact, Supporting Material) for a session, leading with its most-severe finding and
listing the remaining findings.

### 5. Evidence and severity inclusion controls

Reports include finding evidence and severity by default, with an option to omit evidence when
a redacted/short report is wanted.

## Impact

- Adds the `report-generation` capability to `openspec/specs/`.
- First consumer of `result-persistence` beyond the scan engine itself.
- No network access; reports are derived purely from stored data.
