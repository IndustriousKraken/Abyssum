## Why

Broken Access Control (BAC) is the most impactful and common class of API vulnerability:
endpoints that should require authentication or an elevated role are instead reachable by
anyone. This scanner probes a curated set of administrative and sensitive paths
*unauthenticated* and reports the ones that respond as if the caller were authorized.

It follows the scanner template established by `add-rest-discovery-scanner`. It depends on
the scan-orchestration engine (`add-scan-orchestration`) for the base scanner trait, scan
context, progress updates, and cancellation, and on rate limiting (`add-rate-limiting`) so
probing stays within the user's pacing floor.

## What Changes

### 1. Unauthenticated probing of sensitive endpoints

Probe a target's base URL against a curated wordlist of admin/sensitive paths, issuing each
request with any authorization credentials stripped, through the shared scan engine (so
pacing, cancellation, and progress all apply).

### 2. Unauthorized-access detection

Decide, per path, whether the unauthenticated response indicates a broken access control:
a success response carrying sensitive content, or a success response on an
administrative/sensitive endpoint, is flagged; recognized not-found / error pages are
discarded to suppress false positives.

### 3. Redirect-target follow-through

When a sensitive path redirects to another sensitive location, follow the redirect once and
evaluate whether that target is itself reachable unauthenticated, so a redirect does not
mask an exposed admin interface.

### 4. Finding reporting with evidence

Report each unauthorized-access finding with the endpoint, observed HTTP status, and
evidence of exposure (the sensitive-content signals or admin-interface signals observed and
a bounded response sample), with severity reflecting endpoint sensitivity and exposed data.

### 5. Registration in the scanner registry

Register the scanner under the stable id `bac` so the CLI and web surfaces can select and
run it.

## Impact

- Adds the `bac-scan` capability to `openspec/specs/`.
- Consumes `scan-orchestration` and `rate-limiting`; a sibling of the other scanners.
- Reuses the scanner spec/design/tasks template from `add-rest-discovery-scanner`.
