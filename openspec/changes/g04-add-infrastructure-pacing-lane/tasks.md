# Tasks

- [ ] Add a way to mark an outbound request as a support-infrastructure lookup vs target
      traffic (e.g. a field on the request spec), defaulting to target traffic.
- [ ] Mark the scanners' support lookups as such: the DoH resolver queries in
      `subdomain_recon`, the crt.sh passive query, the RDAP queries in `asn_enumeration`, and
      any other third-party discovery source.
- [ ] In the rate limiter, pace support lookups by a separate policy that is not held to the
      target floor and is not stopped by the target-distress halt, but still backs off on a
      rate-limit signal from the support service.
- [ ] Add configuration for the support lane (a faster delay window and higher concurrency),
      with bounded defaults — fast, but not abusive toward a public resolver.
- [ ] Keep target traffic entirely unchanged: floor, backoff, and distress halt as before.
- [ ] Generalize the pacing draw so a request's delay comes from the active policy (target
      policy by default; support policy for support lookups), uniform-by-default preserved.
- [ ] Test: support lookups are not delayed at the target floor; target probes are; a support
      service returning a rate-limit signal still triggers backoff; a big brute-force run's
      resolver phase completes far faster than the same count of target probes would.
