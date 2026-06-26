# Tasks

## 1. Argument parsing
- [x] 1.1 Define the `abyssum` CLI parser: repeatable `--targets` and `--scanners`, plus `--min-delay`, `--max-delay`, `--log-level`, `--output`, and an optional `--config`
- [x] 1.2 Validate `--scanners` against the orchestrator registry's `available()` ids (the source of truth, not a duplicated hardcoded enum); restrict `--output` to `table`/`json`/`csv`
- [x] 1.3 Require at least one target and one scanner; surface usage on `--help` and `--version`

## 2. Input validation
- [x] 2.1 Parse and validate each target URL; default to `https` when no scheme is given
- [x] 2.2 Reject unparseable targets and unknown scanner ids before any request is issued, with a clear error
- [x] 2.3 Unit-test validation: scheme defaulting, garbage URL rejection, unknown-scanner rejection

## 3. Config and logging from flags
- [x] 3.1 Build the run config: defaults < file < env < CLI flags, with `--min-delay`/`--max-delay` setting the pacing window and `--log-level` the verbosity
- [x] 3.2 Initialize logging at the chosen level before the scan starts
- [x] 3.3 Unit-test that CLI flags override file/env values for the run only

## 4. Scan execution
- [x] 4.1 Register the selected scanners in the orchestrator's scanner registry
- [x] 4.2 Create a scan session for the targets/scanners and execute it through the shared engine
- [x] 4.3 Drain progress updates to the terminal while the scan runs (plain log lines when not a TTY)

## 5. Persistence
- [x] 5.1 Ensure the run's session and findings are stored through the persistence layer, identically to web-initiated scans
- [x] 5.2 Integration-test that after a CLI run the session and its findings are retrievable from persistence

## 6. Output rendering
- [x] 6.1 Implement the table renderer (columns: scanner, target, status, severity, title) as the default
- [x] 6.2 Implement the JSON renderer (machine-readable findings)
- [x] 6.3 Implement the CSV renderer with a stable header row, escaping embedded commas and newlines
- [x] 6.4 Unit-test each renderer over a fixed findings fixture; assert all three reflect the same findings

## 7. Exit status
- [x] 7.1 Exit 0 on a completed scan
- [x] 7.2 Exit non-zero on bad input, scan failure, or interruption
- [x] 7.3 Test exit codes for success, unknown scanner, and unparseable target

## 8. End-to-end (local only — no real targets)
- [x] 8.1 Integration-test a full run against a local mock HTTP server: session persisted, findings returned, all three output formats reflect the same findings
