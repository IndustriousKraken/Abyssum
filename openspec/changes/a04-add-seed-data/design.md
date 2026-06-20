# Design: Seed Data Store

## Technical Approach

Reference data ships as bundled assets under `assets/seed/`, embedded into the binary at
build time (`include_str!` / `include_dir!`), and copied into SQLite on first run. This keeps
the "single self-contained binary" promise (canon) while making the data live in the database
(queryable, extensible) rather than locked in constants.

Each asset file seeds one **named list**. A scanner loads one or more lists *by name* — the
"one scanner, many lists" cases (rest, bac, graphql) are why lookup is keyed by list name, not
by scanner id. `subdomains` belongs to no scanner (a target helper); `cors` and `idor` seed no
list (CORS crafts origins inline; IDOR uses inline reference lists).

| Asset file | List name | Loaded by | Entry form |
|---|---|---|---|
| `endpoints.txt` | `rest_endpoints` | rest_discovery | plain value |
| `api_bases.txt` | `rest_api_bases` | rest_discovery | plain value |
| `openapi_paths.txt` | `openapi_paths` | openapi_discovery | plain value |
| `paths.txt` | `bac_paths` | bac | plain value |
| `paths_short.txt` | `bac_paths_short` | bac (fast profile) | plain value |
| `paths_graphql.txt` | `graphql_paths` | graphql | plain value |
| `graphql_queries.txt` | `graphql_queries` | graphql | `label\|body` → `(label, value)` |
| `subdomains.txt` | `subdomains` | (target helper) | plain value |

`user-agents.json` is a categorized UA pool with a `realistic` flag per entry.

## Schema (owned here, extends the persistence DB)

Committed shape (not left open — scanners query this, so a wrong guess would force a later
`MODIFIED`):

```sql
CREATE TABLE wordlists (
    name        TEXT PRIMARY KEY            -- e.g. 'rest_endpoints', 'graphql_queries'
);
CREATE TABLE wordlist_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    list_name   TEXT NOT NULL,             -- FK -> wordlists.name
    value       TEXT NOT NULL,             -- the path / query body
    label       TEXT,                      -- entry label, e.g. a GraphQL query name; NULL for plain lists
    position    INTEGER NOT NULL,          -- preserves seeded order
    UNIQUE(list_name, value)               -- natural identity → idempotent re-seed
);
CREATE TABLE user_agents (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    value       TEXT UNIQUE NOT NULL,
    category    TEXT,                      -- e.g. browser, mobile, scanner
    realistic   BOOLEAN NOT NULL           -- default rotation pool is realistic = true
);
```

`graphql_queries.txt` lines are `label|body`; the seeder splits on the first `|` into
`(label, value)`. Uses `sqlx` migrations (consistent with `result-persistence`).

## Seeding

- On startup, if the store is empty (or a content hash differs), populate from the embedded
  assets. Idempotent: keyed by natural identity (list name + value; UA value), so re-seeding
  inserts only what's missing.
- Optionally exposed as an explicit `abyssum init`/`--seed` path for installers, but first-run
  self-seeding is the primary mechanism so it works regardless of install method.

## User-Agent rotation

- The default rotation pool is the `realistic: true` subset (browsers + mobile). The
  scanner-signature entries (`Abyssum/2.0 (Security Scanner)`, generic scanner, curl,
  python-requests, Googlebot) are present for explicit opt-in but excluded from the default
  pool — picking one of those by default would defeat the stealth posture.
- This change supplies the engine's `UserAgentSource` seam (defined by `add-scan-orchestration`)
  with a rotating implementation backed by the realistic pool. `ScanContext::send` calls the
  source once per request, so every outbound scan request gets a realistic, varied UA without
  any scanner involvement — the rotation actually reaches the wire because there is no unpaced
  request path. Rotation granularity (per-request by default; per-scan optional) is governed by
  a `scanning.user_agent_rotation` config key this change adds.

## Testing

- Seeding is idempotent: seed twice, assert no duplicate entries.
- Wordlists load by scanner id and match the bundled asset counts.
- Default UA selection only ever returns `realistic` entries; opt-in can reach the others.
- All tests run against a temporary SQLite database; no network, no real targets.
