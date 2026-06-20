# Tasks

## 1. Bundled assets
- [ ] 1.1 Embed `assets/seed/wordlists/*.txt` and `assets/seed/user-agents.json` into the binary at build time
- [ ] 1.2 Parse `user-agents.json` into structured entries (name, category, value, realistic flag)

## 2. Store schema
- [ ] 2.1 Add migrations for `wordlists(name)` and `wordlist_entries(list_name, value, label, position)` with `UNIQUE(list_name, value)` and order preserved by `position`
- [ ] 2.2 Add a migration for the `user_agents(value, category, realistic)` table

## 3. Idempotent seeding
- [ ] 3.1 On startup, seed the store from the embedded assets, topping up any missing rows (no content-hash or version check)
- [ ] 3.2 Make seeding idempotent (key by list name + value, and by UA value); re-seeding inserts only missing rows
- [ ] 3.3 Provide an explicit seed entry point the installer/CLI can invoke

## 4. Wordlist access
- [ ] 4.1 Expose a lookup that returns a named list's entries (value + optional label) in seeded order
- [ ] 4.2 Split `graphql_queries.txt` lines on the first `|` into `(label, value)` during seeding
- [ ] 4.3 Return a clear, empty result (not a panic) when a requested list name is absent

## 5. User-Agent rotation
- [ ] 5.1 Implement a `UserAgentSource` (the orchestration seam) that returns a User-Agent from the `realistic` subset by default, varied across calls
- [ ] 5.2 Wire this source into the engine so `ScanContext::send` stamps a rotating UA on every outbound request; add the `scanning.user_agent_rotation` config key (per-request default)
- [ ] 5.3 Allow explicit opt-in to a specific/non-realistic User-Agent

## 6. Tests (local only)
- [ ] 6.1 Seed twice against a temp DB; assert no duplicate wordlist or UA rows
- [ ] 6.2 Assert each named list loads, matches the bundled asset count, and `graphql_queries` entries carry both label and body
- [ ] 6.3 Assert default UA selection only returns `realistic` entries and is not identical across many selections; opt-in can reach the others
