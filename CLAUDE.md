# CLAUDE.md

Guidance for Claude Code working in this repository.

> This repo is under rapid, automated development. This file deliberately does **not**
> describe the current build state (which changes are spec'd vs. implemented, which crates
> are filled in) — that goes stale by the day. Read the code and `openspec/` for what
> exists right now; treat anything here as durable intent only.

## What Abyssum is

An API vulnerability scanner for **authorized** bug-bounty / security testing: REST &
OpenAPI discovery, CORS, BAC, IDOR, and GraphQL scanners, with a CLI and an HTMX/Alpine web
UI sharing one engine. It is a pure-Rust v2 rebuild of an earlier tool.

## Source of truth

The specifications in `openspec/` are the binding contract; the code implements them.

- `openspec/project.md` — the **canon**: product intent, locked technical decisions,
  the binding **Design Philosophy (stealth & infrastructure respect)**, and non-goals.
- `openspec/specs/<capability>/spec.md` — canonical requirements (the binding contract).
- `openspec/changes/<name>/` — in-flight changes (proposal, design, tasks, delta specs);
  `openspec/changes/IMPLEMENTATION_ORDER.md` records the intended build sequence.
- `openspec/future-capabilities.md` — preserved intent for deferred features.
- `assets/seed/` — curated wordlists + User-Agent pool, seeded into the DB on first run.

`openspec/specs/` (canon) and `openspec/changes/archive/` are **autocoder-owned**: do not
edit them directly and do not run `openspec archive`. See `OCTOPUS.md` for the full
issues/change protocol, ownership rules, and gate model — read it before planning work.

## Architecture

A Cargo workspace: a surface-agnostic core engine plus thin surfaces over it.

- `abyssum-core` — config, error model, logging, the rate limiter, scan orchestration
  (the `BaseScanner` contract, `ScanContext`, registry, sessions), persistence, seed data.
- `abyssum-scanners` — the individual scanner implementations, registered into the engine.
- `abyssum-cli` — the `abyssum` binary.
- `abyssum-web` — the `abyssum-web` binary (axum + HTMX/Alpine, WebSocket live progress).

All outbound HTTP flows through `ScanContext::send`, so the pacing floor and User-Agent
rotation cannot be bypassed.

## Locked stack (see project.md for the full list)

- **Pure Rust** — Tokio, axum, reqwest (rustls), sqlx/SQLite. No Python. No `pyo3`.
- Frontend: **HTMX + Alpine**, server-rendered, WebSocket for live progress.
- Multi-user with authentication; outbound OpenAI-compatible AI assist (keyless endpoints
  supported).
- Distribution: cross-compiled static binaries (`abyssum`, `abyssum-web`) + `install.sh`.
- License: **MIT OR Apache-2.0**.

## Defining principle

Abyssum's **default configuration must not DoS the target and must not trip a basic
IDS/IPS** — conservative randomized pacing, a hard floor on delay, distress-aware backoff,
and realistic rotating User-Agents. Aggression is opt-in. This is the project's identity;
preserve it in every change.

## Building & testing

- `cargo build` / `cargo build --release` — build the workspace.
- `cargo test` — run the test suite.
- `cargo clippy --all-targets` and `cargo fmt` — lint and format.
- `openspec validate --strict` — validate spec changes before they're considered ready.

## Workflow

- Work on `dev` or a feature branch; keep `master` clean to avoid merge conflicts.
