## Why

A permissive CORS policy lets an attacker's site read authenticated API responses from a
victim's browser. The CORS scanner detects these misconfigurations by replaying a request
with crafted `Origin` headers and inspecting which origins the server is willing to trust —
especially when it also allows credentials. This is high-signal, low-noise reconnaissance
that maps directly to reportable bug-bounty findings.

It depends on the scan-orchestration engine (`add-scan-orchestration`) for the scanner
trait, session lifecycle, and progress reporting, and on rate limiting
(`add-rate-limiting`) so probing stays within the user's pacing floor.

## What Changes

### 1. Origin probing with crafted headers

Probe the target by issuing requests that carry a set of crafted `Origin` header values —
an attacker-controlled origin, a `null` origin, an origin that merely contains the target's
domain as a substring (untrusted look-alike), and a non-default scheme/port — each request
flowing through the shared scan engine so pacing, cancellation, and progress all apply.

### 2. Permissive-CORS detection

Inspect the `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials`
(ACAC) response headers to detect: a reflected arbitrary origin, a wildcard ACAO combined
with credentials, acceptance of a `null` origin, trusting of an untrusted look-alike origin,
and a bare wildcard without credentials.

### 3. Severity reflecting exploitability

Assign each finding a severity that tracks how exploitable it is — credentialed exposure
(reflected/known origin or wildcard with credentials) ranks higher than the same
misconfiguration without credentials.

### 4. Registration in the scanner registry

Register the scanner under the stable id `cors` so the CLI and web surfaces can select and
run it.

## Impact

- Adds the `cors-scan` capability to `openspec/specs/`.
- Consumes the `scan-orchestration` and `rate-limiting` contracts established earlier.
- Follows the scanner spec/design/tasks template set by `add-rest-discovery-scanner`.
