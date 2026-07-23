# Tasks

- [ ] Make the reference store writable for per-user wordlists (distinct from the seeded
      lists), with a schema that records the owner; ensure re-seeding the built-in lists does
      NOT touch user lists.
- [ ] Add import (paste + `.txt` upload) in the web UI, owned by the authenticated user;
      enforce a sane maximum upload size.
- [ ] Normalize on import (trim, drop blank/comment lines, lowercase, dedupe) and return an
      import report (imported N, dropped M by reason).
- [ ] Add a wordlist selector to the scan form; carry the choice as a per-scan option
      (`g03-add-per-scan-options`).
- [ ] Have wordlist-consuming scanners use the selected list, else the seeded default; entries
      still pass through the DNS-label validation and apex-scope confinement from
      `g01-enforce-recon-scope-invariant`.
- [ ] Make the per-scan wordlist bound configurable; report truncation instead of dropping
      silently.
- [ ] Test: paste/upload stores a normalized list with a correct report; one user cannot see
      another's; a selected list is used and the default applies otherwise; an over-bound list
      is truncated visibly.
