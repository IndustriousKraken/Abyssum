# Tasks

- [x] Add a CLI `diff` command taking two stored session identifiers (older, newer);
      error clearly if either identifier is unknown.
- [x] Match findings across the two sessions by a stable key (scanner id + normalized
      target/endpoint + finding class), reusing the same key as finding consolidation.
- [x] Report added (in newer only), resolved (in older only), and changed (matched but
      differing severity or status) findings; omit unchanged findings from the detail
      list (a summary count is acceptable).
- [x] Support the existing output formats where practical (at least table and JSON).
- [x] Test: two sessions with a known added / removed / changed finding produce exactly
      those three categories; identical sessions produce an empty delta.
