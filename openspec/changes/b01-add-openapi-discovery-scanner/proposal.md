## Why

Many APIs publish a machine-readable contract — an OpenAPI/Swagger document — at a
predictable location. When that document is publicly reachable it hands an operator the
entire documented surface (paths, operations, structure) in one request, which is both a
high-value reconnaissance win and, often, an exposure worth reporting. The OpenAPI
discovery scanner locates such a document and turns it into a finding with the documented
endpoints as evidence.

It follows the `add-rest-discovery-scanner` template and depends on the scan-orchestration
engine (`add-scan-orchestration`) for the scanner trait, session lifecycle, and progress
reporting, and on rate limiting (`add-rate-limiting`) so probing stays within the user's
pacing floor.

## What Changes

### 1. Spec-document probing via common locations and wordlist

Probe a target's base URL against a curated set of common OpenAPI/Swagger document
locations, issuing one request per candidate path through the shared scan engine (so
pacing, cancellation, and progress all apply).

### 2. Spec validation and endpoint extraction

When a candidate response is a genuine OpenAPI/Swagger document, report a finding and
extract the documented endpoints and structure as evidence; distinguish a real spec
document from an unrelated 2xx response so arbitrary JSON/HTML pages are not reported.

### 3. Registration in the scanner registry

Register the scanner under the stable id `openapi_discovery` so the CLI and web surfaces
can select and run it.

## Impact

- Adds the `openapi-discovery` capability to `openspec/specs/`.
- Consumes the `scan-orchestration` and `rate-limiting` contracts established by changes
  a02 and a01, alongside `rest-discovery` (b00).
- Follows the scanner spec/design/tasks template from `add-rest-discovery-scanner`.
