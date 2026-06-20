# Design: CLI

## Technical Approach

The `abyssum` binary (the `abyssum-cli` crate) is a thin shell over `abyssum-core`. It
parses arguments, builds a `Config` overlaid with CLI flags, registers the selected
scanners in the orchestrator, creates a scan session, drives it to completion while
streaming progress, then renders the persisted findings in the requested format.

```
parse args (clap)
  -> validate targets, resolve scanner ids
build Config (defaults < file < env < CLI flags)
init logging at the chosen level
open persistence, build orchestrator + scanner registry
create scan session (targets, scanners)
execute session, draining progress updates to the terminal
render session findings as table | json | csv
exit 0 on success, non-zero on failure
```

The CLI owns no scanning, pacing, or storage logic — those live in `abyssum-core`. This is
the same engine the web surface uses, so the two cannot drift in behavior.

## Library Choices

- **Argument parsing:** `clap` (derive). Targets and scanners are repeatable args; output
  format and log level are `ValueEnum`s. The binary is named `abyssum`.
- **Scanner selection:** the orchestrator's scanner registry is the single source of truth
  for valid scanner ids. `--scanners` values are validated against `registry.available()` (not
  a duplicated hardcoded `ValueEnum`, which would silently drift as scanners are added), and
  unknown ids are rejected before any work starts. The current ids are `rest_discovery`,
  `openapi_discovery`, `cors`, `bac`, `idor`, `graphql`.
- **Output rendering:**
  - *table* — `comfy-table` for an aligned, human-readable summary (columns: scanner,
    target, status, severity, title). Optional color via `colored`/`comfy-table` styling.
  - *json* — `serde_json` pretty-print of the findings.
  - *csv* — `csv` crate (or a minimal hand-rolled writer) with a stable header row; embedded
    commas/newlines in fields are escaped so the output stays parseable.
- **Progress:** drain the orchestrator's progress events; render with `indicatif` when
  attached to a TTY, falling back to plain log lines otherwise.

## Architecture Decisions

### Decision: Flags override config for the run, not on disk
`--min-delay`, `--max-delay`, and `--log-level` overlay the loaded `Config` for this
invocation only; nothing is written back. Precedence is defaults < file < env < CLI flags,
extending the bootstrap precedence with a CLI layer on top.

### Decision: CLI scans are persisted identically to web scans
The CLI creates a session and stores findings through the same persistence layer; there is
no CLI-only "ephemeral" path. This keeps history complete regardless of which surface
started the scan.

### Decision: One findings set, three renderers
Table, JSON, and CSV are pure projections of the same in-memory findings. No renderer
re-runs scanners or re-queries differently, so the formats can never disagree.

### Decision: Exit codes are script-friendly
Distinct, fixed codes so CI can branch on outcome: `0` success, `1` bad input (unknown
scanner, unparseable target), `2` scan execution failure, `130` user interrupt
(Ctrl-C / SIGINT, the conventional 128+SIGINT). On SIGINT the CLI signals the orchestrator's
cancel path so the scan stops promptly and partial findings are still rendered before exit,
rather than a hard abort.

## Testing

- Unit-test target parsing/validation (scheme added when absent, rejects garbage) and
  scanner-id resolution (rejects unknown ids).
- Unit-test each renderer over a fixed findings fixture: table has expected columns, JSON
  round-trips, CSV has a stable header and escapes commas/newlines.
- Integration-test a full run against a **local mock HTTP server** (no real targets):
  assert a session is created and persisted, findings are returned, and the three output
  formats all reflect the same findings.
- Test exit codes: success is 0; an unknown scanner and an unparseable target are non-zero
  with no requests issued.
