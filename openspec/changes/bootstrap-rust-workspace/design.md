# Design: Bootstrap Rust Workspace

## Technical Approach

A Cargo workspace with four members. `abyssum-core` is the only crate that owns
cross-cutting concerns; the binary crates are thin.

```
abyssum/
├── Cargo.toml                # [workspace], shared deps, version = "2.0.0"
├── abyssum-core/             # lib: config, error, logging, (later) orchestration/persistence/auth
├── abyssum-scanners/         # lib: scanner implementations (empty for now)
├── abyssum-web/              # bin "abyssum-web"
└── abyssum-cli/              # bin "abyssum"
```

## Library Choices

- **Runtime:** `tokio` (workspace dep, `full`).
- **Config:** `serde` + `serde_yaml` for the file; a small env-override pass (env wins over
  file wins over defaults). Prefix env vars `ABYSSUM_`.
- **Errors:** `thiserror` for the library error enum; binaries surface errors with context.
- **Logging:** `tracing` + `tracing-subscriber`, level from config/env (`ABYSSUM_LOG`).
- **CLI:** `clap` (derive) — only `--version`/`--help` wired now; subcommands arrive in #12.

## Architecture Decisions

### Decision: One shared `core`, thin binaries
CLI and web both depend on `abyssum-core`. v1 drift between CLI and web was policed by
fragile consistency tests; here it's structurally impossible because both call the same
engine.

### Decision: Config precedence is defaults < file < env
Deterministic and testable. Missing file is not an error (defaults apply); a malformed file
*is* an error (fail fast).

### Decision: No `pyo3`
The v1 experimental branch's Python bridge is discarded entirely (see `project.md`).

## Config Shape (initial)

```yaml
server:
  host: 127.0.0.1
  port: 8000
database:
  path: data/abyssum.db
scanning:
  min_delay: 1.0      # seconds, hard floor (see rate-limiting, change #3)
  max_delay: 3.0
log:
  level: info
```

Later changes extend this (auth secret, AI provider, etc.) via their own deltas; they must
not redefine keys this change owns without a `MODIFIED` requirement.

## Testing

- Unit tests for config precedence (defaults, file overlay, env override, malformed-file
  error).
- A smoke test that each binary runs `--version` and exits 0.
- No network, no real targets.
