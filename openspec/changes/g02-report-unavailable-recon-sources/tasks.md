# Tasks

- [ ] In `subdomain_recon`, return a source-availability outcome from the passive query
      instead of collapsing every failure to "no candidates".
- [ ] Emit an informational finding when the source errors or returns a non-success status,
      naming the source (and the status, when there was one) and stating that results may be
      incomplete. Keep the existing `tracing::warn!` as well.
- [ ] Emit no such finding when the source responds normally, including when it legitimately
      lists no names.
- [ ] Keep cancellation propagating as `Error::Cancelled` — it is not a source failure.
- [ ] Apply the same treatment to the other external sources in surface mapping (the
      DNS-over-HTTPS resolver used by brute-force, the registration-data source used by ASN
      enumeration) so no scanner in this capability degrades silently.
- [ ] Test: a stubbed failing source and a stubbed non-2xx source each yield the finding; a
      healthy source returning zero names yields no source-availability finding.
