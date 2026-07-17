# Tasks

- [x] Add an opt-in active brute-force discovery source to `subdomain_recon`, gated by a
      config/flag that defaults to OFF.
- [x] Generate candidates by joining the seeded `subdomains` wordlist onto the target apex
      domain; deduplicate against passively-discovered candidates.
- [x] Test each candidate for existence via DNS-over-HTTPS resolution issued through
      `ScanContext::send` (paced, rotating User-Agent); no DNS-resolver dependency.
- [x] Route existing candidates into the same liveness + takeover evaluation as passive
      discovery, so they surface as the same finding types.
- [x] Cap the number of candidates probed and log when the cap truncates the wordlist.
- [x] Test (no real network): with brute-force disabled, no wordlist probing occurs; with
      it enabled and a stubbed resolver, an existing candidate is discovered and evaluated.
