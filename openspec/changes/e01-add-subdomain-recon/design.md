# Design

## Shape: a scanner, not a new subsystem

`subdomain_recon` implements the existing `BaseScanner` contract and registers into
the engine like the other six scanners. Its `Target` is an apex domain; `scan` returns
`Finding`s. This reuses everything already built — the paced `ScanContext::send` path,
User-Agent rotation, cancellation, persistence, and the report/render surface — so the
change adds a scanner module and nothing else. `validate_target` requires a bare host
(no path).

## Passive discovery

Gather candidate subdomains from passive sources that index certificate transparency
and DNS observations (e.g. a CT-log aggregator such as crt.sh, and/or passive-DNS
APIs). All queries go out through `ScanContext::send`, so they are paced under the
source's own domain in the rate limiter and carry a rotating User-Agent. The specific
source(s) are implementation guidance, not contract — the binding behavior is "passive
sources, not target DNS brute-force."

## Liveness + takeover, over HTTP only

For each candidate, probe with `ScanContext::send` and classify live vs. dead from the
response (or connection failure). Takeover detection is **HTTP-fingerprint based**:
match the response against known unclaimed-service signatures (the classic
"can-I-take-over-X" fingerprints — e.g. an S3 `NoSuchBucket` body, a GitHub Pages 404,
a Heroku "no such app" page). This deliberately needs no DNS-resolver dependency;
CNAME-chain confirmation is a follow-on slice.

A takeover match is a high-severity vulnerable `Finding`; a live subdomain with no
takeover signature is an informational `Finding` recording the discovered host.

## Pacing note

Probing many discovered subdomains means touching many distinct hosts. The rate limiter
is per-domain and gives each host its first request free, so recon naturally spreads
across hosts rather than hammering one — consistent with the stealth posture. No new
pacing knob is required for this slice.
