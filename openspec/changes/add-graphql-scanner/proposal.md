## Why

GraphQL endpoints concentrate an API's entire surface behind a single route, and a
misconfigured one leaks its full schema through introspection — handing an attacker a map of
every type, query, and mutation. The GraphQL scanner locates GraphQL endpoints on a target,
checks whether introspection is exposed, and reports the schema it can extract, plus the
other GraphQL-specific exposures the v1 scanner probed (unbounded query nesting, query
batching, and sensitive-data disclosure).

It depends on the scan-orchestration engine (`add-scan-orchestration`) for the scanner
trait, session lifecycle, progress events, and cancellation, and on rate limiting
(`add-rate-limiting`) so all probing stays within the user's pacing floor.

## What Changes

### 1. GraphQL endpoint detection

Probe a target's base URL against a curated set of common GraphQL paths, issuing requests
through the shared scan engine, and detect which paths actually serve GraphQL by inspecting
the response shape (GraphQL-style JSON, content type, or GraphQL error indicators).

### 2. Introspection exposure check with schema extraction

Against a detected GraphQL endpoint, send an introspection query. When the server returns
schema data, report a finding and extract schema evidence: type count, query and mutation
field names, and any types whose names suggest sensitive data.

### 3. Additional GraphQL exposure checks

Test the detected endpoint for the further exposures the v1 scanner covered: acceptance of a
deeply nested query (unbounded query depth), query batching (an array request answered with
an array response), and information disclosure from sensitive-data queries — each reported as
its own finding with an assessed severity.

### 4. Registration in the scanner registry

Register the scanner under the stable id `graphql` so the CLI and web surfaces can select and
run it.

## Impact

- Adds the `graphql-scan` capability to `openspec/specs/`.
- Consumes the `scan-orchestration` and `rate-limiting` contracts; follows the scanner
  template established by `add-rest-discovery-scanner`.
