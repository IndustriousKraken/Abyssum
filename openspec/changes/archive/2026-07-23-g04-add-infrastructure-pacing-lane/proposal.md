# Pace support-infrastructure lookups separately from target traffic

## Why

The rate limiter treats every destination the same way — the target's web server and a public
DNS resolver both get the conservative per-domain floor (1–3s, serialized). But those are not
the same kind of thing. The pacing floor exists to avoid stressing or tripping *the target's*
infrastructure. A public DNS resolver, a certificate-transparency aggregator, or a
registration-data service that the operator *chooses* to query in order to map the target is
support infrastructure built for volume, not a target to tread lightly on.

The consequence is concrete: subdomain brute-force resolves candidate names via DNS-over-HTTPS
to Cloudflare's public resolver, all against one domain, so ~2000 lookups serialize at the
target floor — over an hour — for traffic that is invisible to the target and trivial for the
resolver. The entire subdomain-brute-force tooling ecosystem runs these lookups fast against
public resolvers as ordinary practice.

## What Changes

- Requests are classified as **target traffic** (the target or hosts derived from it) or
  **support-infrastructure lookups** (a third-party service queried to discover or map the
  target).
- Support lookups get a separate, configurable pacing policy that is **fast but bounded** —
  not held to the target floor, and not stopped by the target-distress halt — while still
  backing off if the support service itself signals rate limiting (public resolvers do throttle
  abusers).
- Target traffic is unchanged: the hard floor, backoff, and distress halt all still apply.
- The `Randomized Per-Request Pacing` requirement is generalized so a request's delay is drawn
  from the *active pacing policy* (uniform between min and max by default) rather than always
  uniform — which is what lets the support lane, and later a timing profile, supply a different
  policy.

## Note on the shared delta

This change and `g05-add-timing-profiles` both carry an **identical** MODIFY of
`Randomized Per-Request Pacing` (the generalization above). It is intentional and identical in
both, so archiving them in either order is safe — each simply sets the requirement to the same
text. Neither change edits a different part of it.
