# v1 Implementation Order

The rebuild is decomposed into focused changes, each = **one logical unit** that adds one
capability. Change folders are **prefixed** so they sort into build order (the autocoder picks
them up alphabetically) and so each has a short handle — `a02` is easier to say than
`add-scan-orchestration`. The letter groups a phase (`a` spine, `b` scanners, `c` surfaces,
`d` output/meta); the number orders within it.

octopus-autocoder should `apply` → `verify` → `archive` them **in this order**. Every change's
`MODIFIED`/reference depends only on an **earlier** change, so the canon stays internally
consistent at every archive point. All 19 are authored and pass `openspec validate --all`.

> **Shared contract.** The cross-cutting types every scanner and surface speak — `Target`,
> `Finding`, the `Severity` set (`info|low|medium|high|critical`) and the `Status` set
> (`vulnerable|safe|info`) — are defined as binding requirements in **`a02-add-scan-orchestration`**
> and reused everywhere downstream. Do not reinvent them per change.

| # | Handle | Change | Capability (spec domain) | Depends on | Notes |
|---|--------|--------|--------------------------|------------|-------|
| 1 | `a00` | `bootstrap-rust-workspace` | `configuration` | — | Cargo workspace, core crate, config (YAML+env incl. `database.path`), conservative defaults, error model, logging, runnable binaries with `--version/--help`. |
| 2 | `a01` | `add-rate-limiting` | `rate-limiting` | a00 | Random delay floor between min/max, per-domain adaptive backoff on 429/403 **and 5xx/error-rate distress**, first request no delay, floor never reduced. **Precedes orchestration so the `RateLimiter` type exists when the scan context is built.** |
| 3 | `a02` | `add-scan-orchestration` | `scan-orchestration` | a00, a01 | **Owns the shared contract:** `Target`, `Finding`, `Severity`, `Status`; `BaseScanner` trait; `ScanContext` whose only outbound path is a paced `send()` that stamps a rotating UA (no bypass); scanner registry; session lifecycle; progress; cancellation. |
| 4 | `a03` | `add-result-persistence` | `result-persistence` | a00, a02 | SQLite schema for sessions + findings (canonical `Finding` shape, public `finding_id`, recommendations); survive restart; query/filter by status/severity/scanner/target/date/free-text; summary counts. |
| 5 | `a04` | `add-seed-data` | `seed-data` | a02, a03 | Curated wordlists (named lists) + UA pool in DB; idempotent first-run seeding from `assets/seed/`; supplies a02's `UserAgentSource` with the realistic rotating pool (stealth default). |
| 6 | `b00` | `add-rest-discovery-scanner` | `rest-discovery` | a02, a04 | Wordlist endpoint discovery + classification. **Scanner template.** |
| 7 | `b01` | `add-openapi-discovery-scanner` | `openapi-discovery` | a02, a04 | Locate + parse OpenAPI/Swagger docs. |
| 8 | `b02` | `add-cors-scanner` | `cors-scan` | a02 | Detect permissive/reflected origins + credentialed exposure (origins crafted inline). |
| 9 | `b03` | `add-bac-scanner` | `bac-scan` | a02, a04 | Unauthorized access to admin/sensitive endpoints. |
| 10 | `b04` | `add-idor-scanner` | `idor-scan` | a02 | Object-reference enumeration via `Target.id_template`; inline reference lists. |
| 11 | `b05` | `add-graphql-scanner` | `graphql-scan` | a02, a04 | Introspection exposure + schema extraction (`graphql_queries` entries carry label+body). |
| 12 | `c00` | `add-custom-requests-tool` | `custom-requests` | a00 | Manual HTTP request builder; bearer/cookie/header auth; **keyless allowed**. CLI + web. |
| 13 | `c01` | `add-cli` | `cli` | a02, a03, b00–b05 | `abyssum` binary: select targets/scanners (validated against the registry), table/json/csv output, fixed exit codes. |
| 14 | `c02` | `add-authentication` | `authentication` | a00, a02, a03 | Local accounts (Argon2id), `auth_sessions`, `admin` role. Adds `owner_user_id` to scan sessions via its own migration + a `MODIFIED` on persistence; stamps owner at creation (needs a02's create path). |
| 15 | `c03` | `add-web-interface` | `web-ui` | a02, a03, b00–b05, c00, c02 | axum + HTMX/Alpine, concrete route table, registration + login, dashboard, start/cancel scans, live progress (WebSocket), behind auth. |
| 16 | `d00` | `add-annotations` | `annotations` | a03, c02, c03 | Scan/finding notes (anchored to `finding_id`) + color tags, searchable. |
| 17 | `d01` | `add-report-generation` | `report-generation` | a03, c01 | Markdown / JSON / CSV / HackerOne exports; `report` CLI command. Reportable = `status==vulnerable`; "type" = scanner id. |
| 18 | `d02` | `add-ai-assist` | `ai-assist` | a00, a03, c03 | Outbound OpenAI-compatible analysis of a finding; configurable base URL + model; optional/absent API key; web "Analyze with AI" action. |
| 19 | `d03` | `add-distribution` | `distribution` | a00, c01, c03 | Release workflow (cross-compiled static binaries + SHA-256) and `install.sh`. |

## Sequencing rationale

- **a00–a04 are the spine** (config, rate-limiting, orchestration, persistence, seed-data).
  Every scanner and surface depends on them, so they archive first.
- **Rate-limiting (a01) precedes orchestration (a02)** because the scan context holds a
  `RateLimiter`; building orchestration first would reference a type that doesn't exist yet.
- **Orchestration (a02) precedes persistence (a03)** because persistence stores the canonical
  `Finding`/`Target` shapes that a02 defines.
- **Seed-data (a04) precedes the scanners** because every scanner sources its wordlists from
  the seeded store (by named list) and the rotating User-Agent pool flows through a02's UA seam.
- **Scanners b00–b05 are independent siblings** — after a02/a04 they can be built in any order
  or in parallel. Each adds its own capability domain, so their deltas never collide.
- **Auth (c02) precedes web (c03)** because the web UI is specified as being behind
  authentication. Auth also depends on a02 (it stamps the owner onto the session at creation).
- **CLI (c01) needs the scanners** to have something to run; it does not need auth or web.
- **Distribution (d03) is last** — it packages binaries that only exist once CLI + web do.

## Authoring rules (apply to every change)

- `proposal.md` → `## Why` + `## What Changes`. `design.md` (optional) holds tech/library
  choices. `tasks.md` → numbered, **agent-executable** steps only.
- **No task may** archive/sync specs, request human approval, deploy, or hit a real target.
  Scanner verification uses **local mock servers / fixtures only**.
- Delta specs (`specs/<capability>/spec.md`) use `## ADDED Requirements` with complete
  `### Requirement:` + `#### Scenario:` bodies. Reuse exact requirement headers when a
  later change `MODIFIED`s an earlier one (e.g. `c02` modifies persistence's
  "Durable Scan Session Storage" to add the owner).
