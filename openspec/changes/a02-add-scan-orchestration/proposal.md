## Why

Every scanner and both surfaces (CLI, web) need a single engine that runs a chosen set of
scanners against one or more targets, tracks the session through its lifecycle, streams
progress, and stops promptly when cancelled. Without this spine, each scanner would have to
reinvent selection, sequencing, progress, and cancellation — exactly the drift the v2
rebuild exists to prevent (see `openspec/project.md`).

This change defines the orchestration vocabulary the rest of the build depends on: how a
scanner is identified and selected, what a scanner is handed when it runs, how a scan
session is observed and aggregated, and how cancellation surfaces partial results. The REST
discovery scanner exemplar (`add-rest-discovery-scanner`) already references these concepts,
so this change must define them precisely.

It builds only on `bootstrap-rust-workspace` (config, error model, logging).

## What Changes

### 1. Base scanner contract

Define a uniform scanner contract: every scanner exposes stable identity (a stable scanner
id, a human name, a description) and a single operation that scans one target and returns
zero or more findings. Scanners own no cross-cutting concerns (HTTP, pacing, progress,
cancellation) — those arrive via the scan context.

### 2. Scanner registry and selection by stable id

A registry exposes the available scanners, each addressable by its stable id. A scan selects
scanners by id; selecting an unknown id is rejected with a clear error before the scan runs.

### 3. Scan context handed to each scanner

When the engine runs a scanner it provides a scan context giving the scanner the means to
issue HTTP requests, pace those requests through the shared rate limiter, report progress,
and observe a cancellation signal. The scanner uses these rather than creating its own.

### 4. Scan session lifecycle and finding aggregation

A scan session runs the selected scanners across all targets, aggregates every finding into
the session, and moves through observable lifecycle states: running, then completed,
cancelled, or errored. A scanner failing on one target does not abort the whole session.

### 5. Progress events during a scan

While a session runs, the engine emits progress updates carrying how many units have been
tested out of the total and what is currently being tested, so a surface can render live
progress.

### 6. Cancellation with prompt partial results

A running session can be cancelled. On cancellation, scanners stop issuing new requests
promptly, the session transitions to the cancelled state, and the findings gathered so far
remain available.

## Impact

- Adds the `scan-orchestration` capability to `openspec/specs/`.
- Unblocks all six scanner changes (b00–b05) and the CLI/web surfaces (c01, c03).
- Establishes shared vocabulary — scan context, base scanner contract, finding, scanner id,
  progress update, session lifecycle — reused verbatim by later changes.
