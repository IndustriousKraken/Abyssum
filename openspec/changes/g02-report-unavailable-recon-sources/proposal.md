# Report an unavailable discovery source instead of returning silence

## Why

Subdomain reconnaissance depends on an external certificate-transparency source. When that
source fails or answers with a non-success status, the scanner logs a warning and returns
**zero candidates**, then completes successfully with no findings. In the web UI — which
shows findings, not logs — that is indistinguishable from "this domain has no subdomains."

Observed in practice: crt.sh returned `502 Bad Gateway`, and a scan of a domain whose
subdomains *are* in certificate transparency reported nothing at all, quickly and without
complaint. For a reconnaissance tool, silently under-reporting is the worst available
failure mode: the operator concludes the surface is clean when it was never examined.

## What Changes

- When an external discovery source is unavailable, errors, or returns a non-success
  response, the scan SHALL emit an **informational finding** naming the source and stating
  that results may be incomplete — visible in the UI, the CLI table, and reports, not only
  in the log.
- A source that answers normally produces no such finding, so the signal stays quiet when
  nothing is wrong.
- Cancellation is not a source failure and keeps its current behavior.

## Out of scope

Adding fallback or additional discovery sources, and retrying a failed source — both worth
doing, but they change what the scanner *finds*; this change only stops it from lying about
what it looked at.
