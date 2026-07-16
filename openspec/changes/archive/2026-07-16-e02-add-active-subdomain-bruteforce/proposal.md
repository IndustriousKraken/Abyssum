# Add active subdomain brute-force (opt-in discovery source)

## Why

Passive discovery (`e01-add-subdomain-recon`) finds what public sources already know.
Active brute-force finds subdomains that were never in a CT log or passive-DNS record —
but it is louder, so it must be an operator's deliberate choice, not the default. This
adds an opt-in active discovery source that complements the passive one and feeds the
same liveness/takeover evaluation.

## What Changes

- Add an opt-in active subdomain brute-force discovery source to the `subdomain_recon`
  scanner: generate candidates from the seeded subdomain wordlist and test each for
  existence.
- It is **disabled by default** — reconnaissance stays passive unless the operator turns
  it on (conservative-by-default, aggression opt-in).
- Candidates confirmed to exist feed the same liveness and takeover evaluation as
  passively-discovered subdomains.

Existence is tested by DNS-over-HTTPS resolution through the existing paced request path,
so no DNS-resolver dependency is added and the traffic is paced like everything else. The
seeded `subdomains` wordlist is already in the reference store.
