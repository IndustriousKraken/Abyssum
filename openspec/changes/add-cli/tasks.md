# Tasks

## 1. Argument parsing
- [ ] 1.1 Define the `abyssum` CLI parser: repeatable `--targets` and `--scanners`, plus `--min-delay`, `--max-delay`, `--log-level`, `--output`, and an optional `--config`
- [ ] 1.2 Restrict `--scanners` to the registered scanner ids (`rest_discovery`, `openapi_discovery`, `cors`, `bac`, `idor`, `graphql`) and `--output` to `table`/`json`/`csv`
- [ ] 1.3 Require at least one target and one scanner; surface usage on `--help` and `--version`

## 2. Input validation
- [ ] 2.1 Parse and validate each target URL; default to `https` when no scheme is given
- [ ] 2.2 Reject unparseable targets and unknown scanner ids before any request is issued, with a clear error
- [ ] 2.3 Unit-test validation: scheme defaulting, garbage URL rejection, unknown-scanner rejection

## 3. Config and logging from flags
- [ ] 3.1 Build the run config: defaults < file < env < CLI flags, with `--min-delay`/`--max-delay` setting the pacing window and `--log-level` the verbosity
- [ ] 3.2 Initialize logging at the chosen level before the scan starts
- [ ] 3.3 Unit-test that CLI flags override file/env values for the run only

## 4. Scan execution
- [ ] 4.1 Register the selected scanners in the orchestrator's scanner registry
- [ ] 4.2 Create a scan session for the targets/scanners and execute it through the shared engine
- [ ] 4.3 Drain progress updates to the terminal while the scan runs (plain log lines when not a TTY)

## 5. Persistence
- [ ] 5.1 Ensure the run's session and findings are stored through the persistence layer, identically to web-initiated scans
- [ ] 5.2 Integration-test that after a CLI run the session and its findings are retrievable from persistence

## 6. Output rendering
- [ ] 6.1 Implement the table renderer (columns: scanner, target, status, severity, title) as the default
- [ ] 6.2 Implement the JSON renderer (machine-readable findings)
- [ ] 6.3 Implement the CSV renderer with a stable header row, escaping embedded commas and newlines
- [ ] 6.4 Unit-test each renderer over a fixed findings fixture; assert all three reflect the same findings

## 7. Exit status
- [ ] 7.1 Exit 0 on a completed scan
- [ ] 7.2 Exit non-zero on bad input, scan failure, or interruption
- [ ] 7.3 Test exit codes for success, unknown scanner, and unparseable target

## 8. End-to-end (local only — no real targets)
- [ ] 8.1 Integration-test a full run against a local mock HTTP server: session persisted, findings returned, all three output formats reflect the same findings
