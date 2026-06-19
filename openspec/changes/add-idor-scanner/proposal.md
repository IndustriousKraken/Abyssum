## Why

Insecure Direct Object Reference (IDOR) is a high-impact access-control flaw: an
application exposes object identifiers (numeric ids, UUIDs, usernames, emails) directly in
URLs or parameters and fails to verify that the requester is authorized to access the
referenced object. The IDOR scanner finds these by establishing a baseline reference and
then probing adjacent or alternative references, reporting when another object's data comes
back without authorization.

It depends on the scan-orchestration engine (`add-scan-orchestration`) for the scanner
trait, scan context, session lifecycle, and progress reporting, and on rate limiting
(`add-rate-limiting`) so probing stays within the user's pacing floor.

## What Changes

### 1. Object-reference discovery and enumeration

Probe a curated set of object-reference endpoint patterns (e.g. `/api/users/{id}`) and
query-parameter shapes (e.g. `?id=1`). For each, establish a baseline reference, then
derive and probe a small set of adjacent/alternative references appropriate to the
identifier's shape (numeric neighbours, well-known UUIDs, common usernames/emails), all
through the shared scan engine so pacing, cancellation, and progress apply.

### 2. Unauthorized-access detection

Detect an IDOR when probing a reference other than the baseline returns a successful
response carrying a *different* object's data, where the request carried no authorization
to that object. Distinguish this from error/not-found pages and from responses identical to
the baseline so the same object echoed back is not reported.

### 3. Finding reporting with evidence

Report a `Finding` for each confirmed IDOR carrying the affected endpoint or parameter, the
reference that was tried, the baseline reference, and evidence (observed status, a bounded
response sample, and any sensitive fields detected). Severity reflects the sensitivity of
the exposed data.

### 4. Registration in the scanner registry

Register the scanner under the stable id `idor` so the CLI and web surfaces can select and
run it.

## Impact

- Adds the `idor-scan` capability to `openspec/specs/`.
- Consumes the `scan-orchestration` and `rate-limiting` contracts.
- Sibling of the other scanners (#5–#10); its delta is self-contained and does not collide.
