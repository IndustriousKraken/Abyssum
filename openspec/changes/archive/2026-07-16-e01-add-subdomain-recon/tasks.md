# Tasks

- [x] Add a `subdomain_recon` scanner implementing `BaseScanner`, registered via
      `register_builtins`; `validate_target` requires a bare host (no path).
- [x] Discover candidate subdomains from passive certificate-transparency / passive-DNS
      source(s), issuing every source query through `ScanContext::send` (paced, rotating
      User-Agent). Do not brute-force the target's DNS in this slice.
- [x] Probe each candidate through `ScanContext::send` to determine liveness; report each
      live subdomain as an informational finding recording the host.
- [x] Detect subdomain takeover by matching the probe response against known
      unclaimed-service fingerprints; emit a high-severity vulnerable finding naming the
      subdomain and the suspected service.
- [x] Deduplicate candidates and cap the number probed to a sane bound; log when the cap
      truncates results rather than silently dropping them.
- [x] Test (no real network): given a stubbed passive source and stubbed HTTP responses,
      a takeover-fingerprinted host yields a takeover finding, a plain live host yields an
      info finding, and a dead host yields neither.
