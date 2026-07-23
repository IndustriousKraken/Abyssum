# ASN enumeration's data source (api.bgpview.io) no longer resolves

## Symptom

`asn_enumeration` returns no findings for any target — including ones with an obvious ASN
(e.g. `google.com` → AS15169). It resolves the domain to an IP fine, then produces nothing.

## Root cause

The scanner's registration-data source is hardcoded to `https://api.bgpview.io/`
(`abyssum-scanners/src/asn_enumeration.rs`, `SOURCE_BASE`). That host **no longer resolves**
— `api.bgpview.io` returns NXDOMAIN (confirmed via Cloudflare DoH: `"Status":3`). The API
appears discontinued. The scanner's failure path returns `Ok(Vec::new())`, so a dead source
becomes "no findings," silently.

(The silent part is separately addressed by `g02-report-unavailable-recon-sources`, which will
surface a source failure as an informational finding. This issue is the dead dependency
itself: even with that, the scan finds nothing because the source is gone.)

## Fix

Replace bgpview with a maintained, durable source. The spec already says "registration-data
sources such as RDAP or WHOIS" — so prefer standards/first-party endpoints over a third-party
aggregator that can disappear:

- **RDAP** (`https://rdap.org/ip/<ip>` bootstrap, or the IANA RDAP bootstrap → the owning
  RIR) — the standardized successor to WHOIS, HTTP/JSON, gives the network + owning org.
- **RIPEstat** (`https://stat.ripe.net/data/network-info/data.json?resource=<ip>` for IP→ASN,
  and `.../data/announced-prefixes/data.json?resource=AS<n>` for the ASN's announced
  prefixes) — a maintained, official RIPE NCC data API that covers both lookups the scanner
  needs (IP→ASN and ASN→netblocks), HTTP/JSON, no new dependency.

Keep the source base configurable (it already is) and route the queries through the
support-infrastructure lane once `g04-add-infrastructure-pacing-lane` lands.

## Tasks

- [x] Point the ASN registration-data source at a maintained endpoint (RDAP and/or RIPEstat);
      update the response parsing to that source's shape.
- [x] Confirm IP→ASN→netblocks works end to end against a known target (e.g. `8.8.8.8` →
      AS15169 with Google's prefixes).
- [x] Keep the source base configurable and the scope-line (enumeration only, no BGP action)
      intact.
- [x] Test the parser against a captured sample of the chosen source's response.
