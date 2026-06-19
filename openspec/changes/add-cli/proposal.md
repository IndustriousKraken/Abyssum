## Why

The `abyssum` command-line binary is the automation/CI surface of the scanner: it lets an
operator select scanners and targets, run them through the shared engine, and get results
back in a machine-readable or human-readable form — without the web UI. It is the first
surface that wires the whole spine together (orchestration + persistence + the scanners)
behind a single command, so it doubles as an end-to-end proof that the engine is usable.

It depends on scan orchestration (`add-scan-orchestration`) for the session lifecycle and
progress events, on result persistence (`add-result-persistence`) so CLI scans are stored
like any other scan, and on the six scanners (#5–#11) so there is something to run.

## What Changes

### 1. Select scanners and targets on the command line

Accept one or more target URLs and one or more scanner ids on the command line, validate
them, and run the selected scanners against every target through the shared scan engine.
Unknown scanner ids and unparseable targets are rejected before any request is issued.

### 2. Configure pacing and verbosity via flags

Expose minimum- and maximum-delay flags that set the request pacing window (the user-set
delay remains a hard floor — see `rate-limiting`), and a log-level flag that controls
output verbosity. These flags override the corresponding configuration values for the run.

### 3. Output results as a table, JSON, or CSV

Render the run's findings in one of three formats chosen by a flag: a human-readable table
(default), JSON, and CSV. The same underlying findings produce each format so the surfaces
never disagree.

### 4. Persist CLI scans like any other scan

A CLI run creates a scan session and stores its findings through the persistence layer, so
results from the command line are queryable and survive restart exactly as web-initiated
scans are.

### 5. Exit status reflects success vs. failure

The process exits 0 when the scan completes and a non-zero status when it fails (bad input,
scan error, or interruption), so the CLI is safe to use in scripts and CI pipelines.

## Impact

- Adds the `cli` capability to `openspec/specs/`.
- First surface to consume orchestration, persistence, and all six scanners together;
  validates those contracts end to end.
- No web, no auth dependency — the CLI is a local-operator tool.
