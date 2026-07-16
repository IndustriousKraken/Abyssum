---
title: Deep surface mapping
status: deferred
added: 2026-07-16
---

Find the infrastructure people forgot they exposed:
- **Subdomain takeover** — dangling DNS pointing at unclaimed cloud resources.
- **Origin-IP discovery** — the real host behind a CDN/WAF, so testing can reach the
  origin the perimeter was meant to hide.
- **ASN / netblock enumeration** — expand from an org to all netblocks/assets it owns.
- **Forgotten cloud assets** — exposed buckets, stale endpoints, abandoned services.

Scope line: asset *enumeration* is in bounds; BGP route *manipulation* is explicitly
out (illegal and off-thesis).
