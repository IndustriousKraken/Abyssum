# Design

Part of the surface-mapping capability, reusing `ScanContext::send`.

**Sources.** RDAP is the primary source — it is HTTP/JSON, so it reuses the engine's
paced request path with no new dependency (query the registry RDAP endpoint for the
target IP → owning org + ASN; query the ASN for its announced prefixes). WHOIS is a
fallback where RDAP is unavailable.

**Flow.** target domain → resolve to an IP (via the DoH path already used by active
brute-force) → RDAP lookup → ASN + organization → announced netblocks/prefixes.

**Output.** Report the ASN and each netblock as findings (the enumerated footprint). A
large org can own many prefixes, so cap the number reported and log truncation rather
than emitting thousands of rows silently.

**Scope line.** Enumeration only — no BGP/route manipulation, no scanning of the
enumerated ranges here (that is the operator's separate, scoped decision).
