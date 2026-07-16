# Tasks

- [ ] Resolve a target domain to an IP where needed (reuse the DoH path), then query RDAP
      for the owning organization and ASN; fall back to WHOIS where RDAP is unavailable.
- [ ] Enumerate the ASN's announced netblocks/prefixes from the registration-data source.
- [ ] Report the ASN and discovered netblocks as findings naming the owning organization.
- [ ] Cap the number of netblocks reported and log when the cap truncates results.
- [ ] Issue every source query through `ScanContext::send` (paced, rotating User-Agent).
- [ ] Do NOT manipulate routing or perform any BGP action, and do not auto-scan the
      enumerated ranges.
- [ ] Test (no real network): a stubbed RDAP response yields the expected ASN and
      netblocks; no routing action is attempted.
