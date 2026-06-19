# Design: Seed Data Store

## Technical Approach

Reference data ships as bundled assets under `assets/seed/`, embedded into the binary at
build time (`include_str!` / `include_dir!`), and copied into SQLite on first run. This keeps
the "single self-contained binary" promise (canon) while making the data live in the database
(queryable, extensible) rather than locked in constants.

```
assets/seed/
├── wordlists/
│   ├── endpoints.txt        # rest_discovery
│   ├── api_bases.txt        # rest_discovery
│   ├── openapi_paths.txt    # openapi_discovery
│   ├── paths.txt            # bac
│   ├── paths_short.txt      # bac (fast profile)
│   ├── paths_graphql.txt    # graphql endpoint locations
│   ├── graphql_queries.txt  # graphql probe queries
│   └── subdomains.txt       # (target helper)
└── user-agents.json         # categorized UA pool, with a `realistic` flag per entry
```

## Schema (sketch — owned here, extends the persistence DB)

- `wordlists(id, name, scanner_id, ...)` and `wordlist_entries(wordlist_id, value, position)`
  — or a single `reference_entries(kind, list_name, value)` table; exact shape is
  implementation detail.
- `user_agents(id, name, category, value, realistic BOOLEAN)`.

Uses `sqlx` migrations (consistent with `result-persistence`).

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
- A UA is selected from the pool per request (or per scan, configurable) and applied to the
  shared HTTP client provided through the scan context.

## Testing

- Seeding is idempotent: seed twice, assert no duplicate entries.
- Wordlists load by scanner id and match the bundled asset counts.
- Default UA selection only ever returns `realistic` entries; opt-in can reach the others.
- All tests run against a temporary SQLite database; no network, no real targets.
