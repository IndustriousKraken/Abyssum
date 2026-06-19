# v1 Implementation Order

The rebuild is decomposed into focused changes, each = **one logical unit** that adds one
capability. They are ordered so every change builds only on **already-archived** specs —
no change's `MODIFIED`/reference depends on a requirement that doesn't exist yet, so the
canon stays internally consistent at every archive point.

octopus-autocoder should `apply` → `verify` → `archive` them **in this order**. Two are
fully drafted as format exemplars (✎); the rest are scoped here and authored next.

| # | Change | Capability (spec domain) | Depends on (archived) | Notes |
|---|--------|--------------------------|------------------------|-------|
| 1 | `bootstrap-rust-workspace` ✎ | `configuration` | — | Cargo workspace, core crate, config (YAML+env), conservative defaults, error model, logging, runnable binaries with `--version/--help`. |
| 2 | `add-scan-orchestration` | `scan-orchestration` | 1 | Scanner trait, scan-session lifecycle, progress events, cancellation, scanner registry. |
| 3 | `add-rate-limiting` | `rate-limiting` | 1 | Random delay floor between min/max, per-domain adaptive backoff on 429/403 **and 5xx/error-rate distress**, first request no delay, floor never reduced. |
| 4 | `add-result-persistence` | `result-persistence` | 1 | SQLite schema for sessions + findings; survive restart; query/filter. |
| 5 | `add-seed-data` | `seed-data` | 4 | Store curated wordlists + UA pool in DB; idempotent first-run seeding from `assets/seed/`; realistic rotating UA by default (stealth). |
| 6 | `add-rest-discovery-scanner` ✎ | `rest-discovery` | 2,3,5 | Wordlist endpoint discovery + result classification. **Scanner template.** |
| 7 | `add-openapi-discovery-scanner` | `openapi-discovery` | 2,3,5 | Locate + parse OpenAPI/Swagger docs. |
| 8 | `add-cors-scanner` | `cors-scan` | 2,3,5 | Detect permissive/reflected origins + credentialed exposure. |
| 9 | `add-bac-scanner` | `bac-scan` | 2,3,5 | Unauthorized access to admin/sensitive endpoints. |
| 10 | `add-idor-scanner` | `idor-scan` | 2,3,5 | Object-reference enumeration / authorization bypass. |
| 11 | `add-graphql-scanner` | `graphql-scan` | 2,3,5 | Introspection exposure + schema extraction. |
| 12 | `add-custom-requests-tool` | `custom-requests` | 1 | Manual HTTP request builder; bearer/cookie/header auth; **keyless allowed**. CLI + web. |
| 13 | `add-cli` | `cli` | 2,4,6–11 | `abyssum` binary: select targets/scanners, table/json/csv output. |
| 14 | `add-authentication` | `authentication` | 1,4 | Local accounts, hashed passwords, server-side sessions, `admin` role. |
| 15 | `add-web-interface` | `web-ui` | 2,4,6–12,14 | axum + HTMX/Alpine, dashboard, start/cancel scans, live progress (WebSocket), behind auth. |
| 16 | `add-annotations` | `annotations` | 4,15 | Scan notes + color tags, searchable. |
| 17 | `add-report-generation` | `report-generation` | 4 | Markdown / JSON / CSV / HackerOne exports of findings. |
| 18 | `add-ai-assist` | `ai-assist` | 4 | Outbound OpenAI-compatible analysis of findings; configurable base URL + model; optional/absent API key. |
| 19 | `add-distribution` | `distribution` | 1,13,15 | Release workflow (cross-compiled static binaries + SHA-256) and `install.sh`. |

## Sequencing rationale

- **1–5 are the spine** (config, orchestration, rate limiting, persistence, seed-data). Every
  scanner and surface depends on them, so they archive first.
- **Seed-data (5) precedes the scanners** because every scanner sources its wordlist from the
  seeded store and uses the rotating User-Agent pool; specifying scanners first would force a
  later `MODIFIED` to redirect their data source.
- **Scanners 6–11 are independent siblings** — after 2/3/5 they can be built in any order or
  in parallel. Each adds its own capability domain, so their deltas never collide.
- **Auth (14) precedes web (15)** because the web UI is specified as being behind
  authentication; specifying web first would force a later `MODIFIED` to bolt auth on,
  which we avoid.
- **CLI (13) needs the scanners** to have something to run; it does not need auth (local
  operator) or the web layer.
- **Distribution (19) is last** — it packages binaries that only exist once CLI + web do.

## Authoring rules (apply to every change)

- `proposal.md` → `## Why` + `## What Changes`. `design.md` (optional) holds tech/library
  choices. `tasks.md` → numbered, **agent-executable** steps only.
- **No task may** archive/sync specs, request human approval, deploy, or hit a real target.
  Scanner verification uses **local mock servers / fixtures only**.
- Delta specs (`specs/<capability>/spec.md`) use `## ADDED Requirements` with complete
  `### Requirement:` + `#### Scenario:` bodies. Reuse exact requirement headers when a
  later change `MODIFIED`s an earlier one.
