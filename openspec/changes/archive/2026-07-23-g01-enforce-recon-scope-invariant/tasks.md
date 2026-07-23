# Tasks

- [x] Add an apex-scope filter applied to the final candidate set in `subdomain_recon`: keep
      only names equal to the apex or ending in `.<apex>`; drop everything else regardless of
      source (passive or brute-force).
- [x] Count the out-of-scope discards and log them (and surface them alongside the other
      truncation/availability reporting rather than dropping them silently).
- [x] Validate wordlist entries as DNS labels in `generate_candidates` — ASCII alphanumeric
      and hyphen, not leading/trailing hyphen, at most 63 characters — rejecting anything
      containing `.`, `/`, `?`, `#`, `@`, `:`, whitespace, or control characters.
- [x] Build the probe URL so the candidate cannot alter the authority (set the host on a
      parsed URL rather than interpolating it into a URL string), and skip any candidate the
      URL type rejects as a host.
- [x] Test: `evil.com#`, `evil.com/`, `evil.com?`, `user@evil.com`, and `a b` produce no
      request to any host outside the apex; a passive source returning `evil.com` is
      discarded; ordinary labels still produce `<label>.<apex>`.
- [x] Test the invariant at the probe boundary, not only at generation, so a future source
      cannot reintroduce the escape.
