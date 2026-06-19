# Tasks

## 1. Bundled assets
- [ ] 1.1 Embed `assets/seed/wordlists/*.txt` and `assets/seed/user-agents.json` into the binary at build time
- [ ] 1.2 Parse `user-agents.json` into structured entries (name, category, value, realistic flag)

## 2. Store schema
- [ ] 2.1 Add migrations for the wordlist store (lists keyed by scanner id + ordered entries)
- [ ] 2.2 Add a migration for the user-agent table including the `realistic` flag

## 3. Idempotent seeding
- [ ] 3.1 On startup, detect an empty/stale store and seed it from the embedded assets
- [ ] 3.2 Make seeding idempotent (key by list name + value, and by UA value); re-seeding inserts only missing rows
- [ ] 3.3 Provide an explicit seed entry point the installer/CLI can invoke

## 4. Wordlist access
- [ ] 4.1 Expose a lookup that returns a scanner's wordlist by scanner id
- [ ] 4.2 Return a clear, empty result (not a panic) when a requested list is absent

## 5. User-Agent rotation
- [ ] 5.1 Expose a selector that returns a User-Agent from the `realistic` subset by default
- [ ] 5.2 Apply the selected User-Agent to outbound scan requests via the shared HTTP client
- [ ] 5.3 Allow explicit opt-in to a specific/non-realistic User-Agent

## 6. Tests (local only)
- [ ] 6.1 Seed twice against a temp DB; assert no duplicate wordlist or UA rows
- [ ] 6.2 Assert each scanner's wordlist loads and matches the bundled asset count
- [ ] 6.3 Assert default UA selection only returns `realistic` entries; opt-in can reach others
