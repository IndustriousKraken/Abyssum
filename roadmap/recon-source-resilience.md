---
title: Resilient multi-source discovery for recon scanners
status: proposed
added: 2026-07-23
---

The recon scanners each depend on a single hardcoded third-party source, and those sources
prove fragile in practice: crt.sh frequently 502s, and api.bgpview.io's hostname stopped
resolving entirely (see issue `asn-source-bgpview-dead`). A single point of failure on a
recon tool means "found nothing" routinely masks "couldn't look."

`g02-report-unavailable-recon-sources` makes a dead source *visible* (an info finding rather than
silence), and per-source issues swap individual dead endpoints — but the structural fix is
resilience: more than one source per capability with fallback, so one flaky provider does not
zero out a scan.

Worth considering later:
- Multiple certificate-transparency / passive-DNS sources for subdomain discovery, tried in
  turn (crt.sh, plus at least one alternative CT aggregator or passive-DNS API).
- Multiple registration-data / routing sources for ASN (RDAP + RIPEstat, etc.).
- A small retry with backoff before declaring a source unavailable.
- Operator-configurable source lists (which ties into user-supplied wordlists / config).

Deferred until the single-source scanners are otherwise solid; this is a reliability
investment, not a new capability.
