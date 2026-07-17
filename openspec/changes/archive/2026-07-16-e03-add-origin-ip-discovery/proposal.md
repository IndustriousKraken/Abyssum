# Add origin-IP discovery (behind CDN/WAF)

## Why

A target served through a CDN/WAF (Cloudflare et al.) hides its real origin. If the
origin answers directly, the perimeter's protections can be bypassed by testing it
straight — but only if you can find it. This adds discovery of the true origin IP so
subsequent testing can reach the host the perimeter was meant to hide. It is squarely
on-thesis: reaching the deeper infrastructure people assume is covered.

## What Changes

- Detect that a target is fronted by a CDN/WAF.
- Gather candidate origin IPs from passive sources (historical/passive DNS, certificate
  data) rather than attacking the perimeter.
- Confirm a candidate by requesting the target host directly against that IP and
  comparing the response to the perimeter-served one; a confirmed origin is reported as a
  finding. Unconfirmed candidates are not reported as the origin.

All lookups and probes flow through the existing paced request path.

## Out of scope

Exploiting the origin — this discovers and confirms it; testing it is the job of the
other scanners. No perimeter stress/attack techniques.
