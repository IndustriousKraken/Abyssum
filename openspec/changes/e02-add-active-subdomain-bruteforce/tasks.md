# Tasks

- [ ] Add an opt-in active brute-force discovery source to `subdomain_recon`, gated by a
      config/flag that defaults to OFF.
- [ ] Generate candidates by joining the seeded `subdomains` wordlist onto the target apex
      domain; deduplicate against passively-discovered candidates.
- [ ] Test each candidate for existence via DNS-over-HTTPS resolution issued through
      `ScanContext::send` (paced, rotating User-Agent); no DNS-resolver dependency.
- [ ] Route existing candidates into the same liveness + takeover evaluation as passive
      discovery, so they surface as the same finding types.
- [ ] Cap the number of candidates probed and log when the cap truncates the wordlist.
- [ ] Test (no real network): with brute-force disabled, no wordlist probing occurs; with
      it enabled and a stubbed resolver, an existing candidate is discovered and evaluated.
