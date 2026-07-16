# Add subdomain reconnaissance (deep surface mapping, first slice)

## Why

Today an operator must already know the host to scan. The highest-leverage next
capability is finding the surface in the first place — the subdomains an org forgot
it exposed — because every discovered host multiplies the value of the scanners that
already exist. This is the first slice of the roadmap's **deep surface mapping**
(`roadmap/deep-surface-mapping.md`): passive subdomain discovery plus subdomain-
takeover detection.

Built passive-first, it stays on-thesis for stealth: subdomains are gathered from
certificate-transparency / passive-DNS sources (querying third parties, not brute-
forcing the target's DNS), so discovery is quiet by default.

## What Changes

- Add a `subdomain_recon` scanner that, given an apex domain, discovers subdomains
  from passive sources, confirms which are live, and detects subdomain takeover.
- Discovered live subdomains are reported as informational findings (the attack
  surface); takeover candidates are reported as vulnerable findings naming the
  subdomain and the suspected unclaimed service.

It plugs in as a scanner (selected with `--scanners subdomain_recon`), so it reuses the
engine's paced request path, User-Agent rotation, persistence, and reporting rather
than introducing a new subcommand or pipeline.

## Out of scope (follow-on slices)

- Active DNS brute-force (an opt-in, noisier dial).
- CNAME/DNS-resolver-based takeover confirmation (this slice is HTTP-fingerprint based).
- Origin-IP-behind-CDN discovery, ASN/netblock enumeration, forgotten-cloud-asset
  discovery — the remaining parts of `roadmap/deep-surface-mapping.md`.
- Automatically feeding discovered subdomains into a follow-on scan (target chaining).
