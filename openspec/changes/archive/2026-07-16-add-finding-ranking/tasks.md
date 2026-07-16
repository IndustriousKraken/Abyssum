# Tasks

- [x] Define a stable finding key (scanner id + normalized target/endpoint + finding
      class/title) used to detect duplicates.
- [x] Collapse findings sharing that key into one reported finding carrying an
      occurrence count; distinct findings are left separate.
- [x] Order reported findings by importance: vulnerable status before safe/info, then
      by severity (critical → info), with a deterministic tie-break so equal-rank
      findings keep a stable order.
- [x] Apply consolidation and ordering at the reporting boundary (CLI render and any
      export) without changing stored raw findings.
- [x] Test: a set with repeated identical findings collapses to one with the right
      count; a mixed-severity set comes back ordered critical-first and deterministic.
