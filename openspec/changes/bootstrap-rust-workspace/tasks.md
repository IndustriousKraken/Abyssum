# Tasks

## 1. Workspace skeleton
- [ ] 1.1 Create root `Cargo.toml` with `[workspace]` members `abyssum-core`, `abyssum-scanners`, `abyssum-web`, `abyssum-cli` and a shared `[workspace.package]` version `2.0.0`
- [ ] 1.2 Create `abyssum-core` lib crate with module stubs `config`, `error`, `logging`
- [ ] 1.3 Create `abyssum-scanners` lib crate (empty `lib.rs` for now)
- [ ] 1.4 Create `abyssum-web` bin crate producing binary `abyssum-web`
- [ ] 1.5 Create `abyssum-cli` bin crate producing binary `abyssum`
- [ ] 1.6 Confirm `cargo build --workspace` links successfully

## 2. Error model
- [ ] 2.1 Define a `thiserror`-based `Error` enum in `abyssum-core::error` (variants for Config, Io, and a catch-all) and a `Result<T>` alias
- [ ] 2.2 Re-export `Error`/`Result` from the crate root

## 3. Configuration
- [ ] 3.1 Define config structs (`server`, `database`, `scanning`, `log`) with `serde` + `Default`
- [ ] 3.2 Implement load order: defaults → overlay YAML file if present → apply `ABYSSUM_*` env overrides
- [ ] 3.3 Return a `Config` error on a malformed file; treat a missing file as "use defaults"
- [ ] 3.4 Unit tests: defaults-only, file overlay, env override wins, malformed-file errors

## 4. Logging
- [ ] 4.1 Initialize `tracing-subscriber` with level from config/`ABYSSUM_LOG`
- [ ] 4.2 Expose a `logging::init(&Config)` entry point both binaries call on startup

## 5. Binary entry points
- [ ] 5.1 `abyssum-web` `main`: init logging, load config, print a startup line, exit cleanly (no server yet)
- [ ] 5.2 `abyssum` (CLI) `main`: `clap` parser exposing `--version` and `--help`
- [ ] 5.3 Smoke tests asserting each binary runs `--version` and exits 0
