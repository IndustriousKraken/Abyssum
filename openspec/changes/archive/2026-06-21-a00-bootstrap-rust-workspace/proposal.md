## Why

The v2 rebuild is a pure-Rust greenfield (see `openspec/project.md`). Before any scanner,
surface, or persistence work can begin, the project needs a buildable Cargo workspace with
the cross-cutting foundations every later change depends on: configuration loading, a
shared error model, structured logging, and runnable binary entry points.

This change establishes that spine so subsequent changes (orchestration, rate limiting,
persistence, scanners) have a stable place to land.

## What Changes

### 1. Create the Cargo workspace and crate layout

A workspace with a shared `abyssum-core` library and two binary crates (`abyssum-web`,
`abyssum-cli`) plus a `abyssum-scanners` library, so the CLI and web surfaces share one
engine and cannot drift. No `pyo3`, no Python.

### 2. Configuration loading

A single configuration system: load defaults, overlay a YAML config file when present, and
allow environment-variable overrides. Invalid configuration fails fast with a clear error
rather than starting in a bad state.

### 3. Shared error model and structured logging

One error type hierarchy used across crates, and structured, level-controlled logging
configurable via config/env.

### 4. Runnable binary entry points

Both binaries start, report `--version` and `--help`, and exit cleanly. This proves the
workspace builds and links end to end and gives CI something to smoke-test.

## Impact

- Establishes `configuration` as the first capability in `openspec/specs/`.
- Unblocks the rest of the spine and all downstream changes in `IMPLEMENTATION_ORDER.md`.
- No user-facing scanning behavior yet.
