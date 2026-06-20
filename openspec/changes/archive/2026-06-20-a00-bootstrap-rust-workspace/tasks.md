# Tasks

## 1. Workspace skeleton
- [x] 1.1 Create root `Cargo.toml` with `[workspace]` members `abyssum-core`, `abyssum-scanners`, `abyssum-web`, `abyssum-cli` and a shared `[workspace.package]` version `2.0.0`
- [x] 1.2 Create `abyssum-core` lib crate with module stubs `config`, `error`, `logging`
- [x] 1.3 Create `abyssum-scanners` lib crate (empty `lib.rs` for now)
- [x] 1.4 Create `abyssum-web` bin crate producing binary `abyssum-web`
- [x] 1.5 Create `abyssum-cli` bin crate producing binary `abyssum`
- [x] 1.6 Confirm `cargo build --workspace` links successfully

## 2. Error model
- [x] 2.1 Define a `thiserror`-based `Error` enum in `abyssum-core::error` (variants for Config, Io, and a catch-all) and a `Result<T>` alias; mark the enum `#[non_exhaustive]` since later changes append variants (e.g. `ScannerNotFound`, storage/auth errors)
- [x] 2.2 Re-export `Error`/`Result` from the crate root

## 3. Configuration
- [x] 3.1 Define config structs (`server`, `database`, `scanning`, `log`) with `serde` + `Default`
- [x] 3.2 Implement load order: defaults → overlay YAML file if present → apply `ABYSSUM_*` env overrides
- [x] 3.3 Return a `Config` error on a malformed file; treat a missing file as "use defaults"
- [x] 3.4 Unit tests: defaults-only, file overlay, env override wins, malformed-file errors

## 4. Logging
- [x] 4.1 Initialize `tracing-subscriber` with level from config/`ABYSSUM_LOG`
- [x] 4.2 Expose a `logging::init(&Config)` entry point both binaries call on startup

## 5. Binary entry points
- [x] 5.1 `abyssum-web` `main`: init logging, load config, print a startup line, exit cleanly (no server yet)
- [x] 5.2 `abyssum` (CLI) `main`: `clap` parser exposing `--version` and `--help`
- [x] 5.3 Smoke tests asserting each binary runs `--version` and exits 0
