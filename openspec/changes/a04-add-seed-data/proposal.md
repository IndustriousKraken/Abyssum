## Why

Abyssum's scanners depend on curated reference data — per-scanner endpoint/path/query
wordlists and a pool of realistic User-Agent strings — that took real effort to assemble and
is part of the product's value. That data must not be hard-coded as throwaway constants: it
should live in the database so it is queryable, inspectable, and extensible at runtime, while
still shipping inside the single self-contained binary.

This change establishes a reference-data store that is seeded once from bundled assets, and
makes the User-Agent pool a first-class **stealth** asset: by default Abyssum blends in with
realistic browser/mobile identities rather than announcing itself to an IDS/IPS (see the
Design Philosophy in `project.md`).

## What Changes

### 1. Store curated reference data in the database

Persist the bundled wordlists (one curated set per scanner that needs one) and the
User-Agent pool in dedicated database tables, so they can be read at runtime and extended
without rebuilding the binary.

### 2. Seed the store from bundled assets on first run

The curated assets ship embedded in the binary. On first run — or whenever the store is
empty — the system seeds the database from them. Seeding is idempotent: running it again
does not duplicate entries.

### 3. Scanners read their wordlists from the store

Each scanner obtains its candidate paths/queries from the seeded store rather than from
compiled-in constants, so the same data backs both probing and any future inspection UI.

### 4. Realistic, rotating User-Agent by default

Outbound scan requests present a User-Agent drawn from the realistic (browser/mobile) subset
of the pool, rotating across requests. Scanner-announcing identities exist in the pool but
are never used unless explicitly selected.

## Impact

- Adds the `seed-data` capability to `openspec/specs/`.
- Sits between `result-persistence` (a03) and the scanners (b00–b05) in the implementation order.
- Preserves the v1 curation (`assets/seed/wordlists/*.txt`, `assets/seed/user-agents.json`)
  through the rewrite instead of regenerating generic lists.
