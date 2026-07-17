# Add ASN / netblock enumeration

## Why

Bug-bounty and assessment scope is usually an organization, not a single host. Expanding
from one domain or IP to the ASN and netblocks the organization actually owns reveals the
full external footprint — the assets a single-host view misses. This is on-thesis surface
mapping: know the real extent of what's exposed.

## What Changes

- Given a target domain or IP, enumerate the autonomous system (ASN) and the IP
  netblocks/prefixes associated with the owning organization, using registration-data
  sources (RDAP/WHOIS).
- Report the discovered ASN and netblocks.

## Scope line

Enumeration only. The system SHALL NOT manipulate routing or perform any BGP action —
asset *enumeration* is in bounds; anything touching BGP route *manipulation* is explicitly
out (illegal and off-thesis). All source queries flow through the paced request path.
