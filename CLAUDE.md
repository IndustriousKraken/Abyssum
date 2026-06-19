# CLAUDE.md

Guidance for Claude Code working in this repository.

## Current state: pre-implementation

This repo holds the **specifications** for Abyssum v2, a pure-Rust rewrite. **The codebase
has not been built yet** — the previous Python implementation was removed deliberately. Do
not look for `core/`, `scanners/`, `web/`, etc.; they no longer exist.

The **source of truth** is `openspec/`:

- `openspec/project.md` — the **canon**: product intent, locked technical decisions,
  the binding **Design Philosophy (stealth & infrastructure respect)**, and non-goals.
- `openspec/changes/IMPLEMENTATION_ORDER.md` — the ordered list of 19 changes to build.
- `openspec/changes/<name>/` — each change's proposal, design, tasks, and delta spec.
- `openspec/future-capabilities.md` — preserved intent for deferred features (e.g. the
  observing proxy).
- `assets/seed/` — curated wordlists + User-Agent pool, seeded into the DB on first run.

Specs follow the [OpenSpec](https://github.com/Fission-AI/OpenSpec) format. Validate with
`openspec validate --all`.

## What Abyssum is

An API vulnerability scanner for **authorized** bug-bounty / security testing: REST &
OpenAPI discovery, CORS, BAC, IDOR, and GraphQL scanners, with a CLI and an HTMX/Alpine web
UI sharing one engine.

## Locked stack (see project.md for the full list)

- **Pure Rust** — Tokio, axum, reqwest, sqlx/SQLite. No Python. No `pyo3`.
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

## Building it

The implementation is driven by an automated coding pipeline (octopus-autocoder) that
applies the changes in `IMPLEMENTATION_ORDER.md`. Once Rust code exists, regenerate this
file (e.g. via `/init`) with real build/test commands.

## Workflow

- Work on `dev` or a feature branch; keep `master` clean to avoid merge conflicts.
