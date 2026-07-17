# Design

Plugs in as part of the surface-mapping capability (a scanner or a mode of the recon
scanner), reusing `ScanContext::send`.

**Detect fronting.** Recognize a CDN/WAF from response headers / IP ownership (e.g.
`Server`/`CF-Ray` markers, known CDN netblocks) to decide whether origin discovery is
worth attempting.

**Gather candidates (passive).** Historical and passive-DNS A records, and IPs seen in
certificate-transparency data for the host — all fetched over HTTP from third-party
sources, not by probing the target's perimeter.

**Confirm.** For each candidate IP, issue a direct request to the IP while presenting the
target's `Host` header (reqwest supports this), and compare the response to the
perimeter-served baseline — a matching body/title/marker with the CDN headers absent
indicates a real origin. Comparison reuses the body-normalization approach already used
by BAC/IDOR. Only confirmed origins are reported (avoids naming every shared-host IP).

**Scope line.** Discovery and confirmation only; no exploitation, no perimeter attacks.
Candidate IP probing is paced per-IP by the rate limiter.
