## Why

REST endpoint discovery is the foundational reconnaissance scanner: it finds undocumented
or hidden API endpoints by probing a target against a curated wordlist. It is the template
the other five scanners follow, so getting its behavior contract right de-risks the rest.

It depends on the scan-orchestration engine (`add-scan-orchestration`) for the scanner
trait, session lifecycle, and progress reporting, and on rate limiting
(`add-rate-limiting`) so probing stays within the user's pacing floor.

## What Changes

### 1. Endpoint discovery via wordlist

Probe a target's base URL against a curated endpoint wordlist, issuing one request per
candidate path through the shared scan engine (so pacing, cancellation, and progress all
apply).

### 2. Result classification

Classify each probed path by what the response indicates — a present/accessible endpoint, a
protected endpoint, or absent — using status codes and response shape, and record findings
with evidence (path, status, salient response signals).

### 3. Registration in the scanner registry

Register the scanner under the stable id `rest_discovery` so the CLI and web surfaces can
select and run it.

## Impact

- Adds the `rest-discovery` capability to `openspec/specs/`.
- First consumer of `scan-orchestration` and `rate-limiting`; validates those contracts.
- Establishes the scanner spec/design/tasks template for changes #6–#10.
