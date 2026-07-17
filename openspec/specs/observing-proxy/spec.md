# observing-proxy Specification

## Purpose
TBD - created by archiving change f01-add-observing-proxy-core. Update Purpose after archive.
## Requirements
### Requirement: Non-Blocking Traffic Pass-Through
The observing proxy SHALL relay HTTP and HTTPS traffic between a client and its
destination without blocking on inspection: the destination's response SHALL be returned
to the client without waiting on capture or analysis, and the proxy SHALL NOT hold traffic
for operator action nor modify it in flight.

#### Scenario: Response is returned without waiting on capture
- **GIVEN** a client request relayed through the proxy
- **WHEN** the destination responds
- **THEN** the response SHALL be returned to the client without waiting on capture or analysis

#### Scenario: Traffic is not held or modified
- **GIVEN** traffic flowing through the proxy
- **WHEN** it is relayed
- **THEN** the proxy SHALL NOT pause it for operator action
- **AND** SHALL NOT alter the request or response in flight

### Requirement: Capture Traffic To A Queryable Store
The observing proxy SHALL capture each relayed request and response into a dedicated
persistent traffic store, recording at least method, endpoint, headers, status, timing,
and body within a size limit. Captured traffic SHALL survive process restart and SHALL be
queryable by endpoint, parameter, header, status, and time. Capture SHALL be asynchronous,
so that a slow or failing store does not stall the proxied client.

#### Scenario: A relayed exchange is captured and retrievable
- **GIVEN** an exchange relayed through the proxy
- **WHEN** capture completes
- **THEN** the exchange SHALL be retrievable from the traffic store with its method, endpoint, headers, status, and timing

#### Scenario: Captured traffic survives restart
- **GIVEN** exchanges captured to the traffic store
- **WHEN** the process restarts and the store is reopened
- **THEN** the previously captured exchanges SHALL still be retrievable

#### Scenario: The store is queryable along key dimensions
- **GIVEN** a populated traffic store
- **WHEN** it is queried by endpoint, parameter, header, status, or time
- **THEN** it SHALL return the matching exchanges

#### Scenario: Capture does not stall the client
- **GIVEN** the traffic store is slow or failing
- **WHEN** an exchange is relayed
- **THEN** the client SHALL still receive its response without waiting on capture

### Requirement: Auto-Flag Security-Relevant Traffic
The system SHALL analyze captured traffic and automatically flag security-relevant
elements: authentication tokens and cookies, object-reference and pagination parameters
(IDOR candidates), API endpoints, and error responses. This analysis SHALL run over the
stored traffic rather than inline in the relay path, so it does not affect the proxy's
non-blocking behavior.

#### Scenario: Authentication material is flagged
- **GIVEN** a captured exchange carrying a bearer token or session cookie
- **WHEN** the traffic is analyzed
- **THEN** the exchange SHALL be flagged as carrying authentication material

#### Scenario: Object-reference parameters are flagged as IDOR candidates
- **GIVEN** a captured exchange with a numeric, UUID, or sequential object-reference or pagination parameter
- **WHEN** the traffic is analyzed
- **THEN** the exchange SHALL be flagged as an IDOR candidate

#### Scenario: Error responses are flagged
- **GIVEN** a captured exchange whose response is a server error
- **WHEN** the traffic is analyzed
- **THEN** the exchange SHALL be flagged as an error response

#### Scenario: Analysis does not block the relay
- **GIVEN** traffic flowing through the proxy
- **WHEN** it is analyzed and flagged
- **THEN** the analysis SHALL run over stored traffic, not inline in the relay path

### Requirement: Score And Surface Interesting Traffic
The system SHALL assign an interest score to captured exchanges from the security-relevant
categories present, and SHALL surface higher-interest exchanges ahead of lower-interest
ones. The score SHALL be a ranking aid, not a verdict.

#### Scenario: Higher-interest traffic is surfaced first
- **GIVEN** one exchange carrying an auth token and an object-reference parameter and another that is a plain static asset
- **WHEN** the interest scoring runs
- **THEN** the first exchange SHALL score higher and be surfaced ahead of the second

### Requirement: Export Captured Traffic
The system SHALL export captured traffic in interchange formats — at least HAR, an OpenAPI
description synthesized from observed endpoints, and raw request/response — so captured
traffic can be consumed by external tools. The synthesized OpenAPI description SHALL be
presented as a best-effort account of observed traffic, not a guarantee of completeness.

#### Scenario: Export to HAR
- **GIVEN** a populated traffic store
- **WHEN** the operator exports to HAR
- **THEN** the captured exchanges SHALL be emitted as a valid HAR document

#### Scenario: Synthesize OpenAPI from observed endpoints
- **GIVEN** captured exchanges across several endpoints
- **WHEN** the operator exports OpenAPI
- **THEN** an OpenAPI description SHALL be produced from the observed endpoints and marked best-effort

#### Scenario: Export raw exchanges
- **GIVEN** a populated traffic store
- **WHEN** the operator exports raw
- **THEN** the verbatim request/response of each exchange SHALL be emitted

### Requirement: Programmatic Access And Replay
The system SHALL expose captured traffic through a read API so external tools and agents
can query it, and SHALL support replaying a captured request with operator-specified
modifications. A replayed request SHALL be issued through the paced request path, and its
response SHALL be captured like any other exchange.

#### Scenario: Captured traffic is queryable via the API
- **GIVEN** a populated traffic store
- **WHEN** an external caller queries the read API
- **THEN** it SHALL return the matching captured exchanges

#### Scenario: A captured request is replayed with modifications
- **GIVEN** a captured request
- **WHEN** the operator replays it with modified fields
- **THEN** the modified request SHALL be issued through the paced request path
- **AND** its response SHALL be captured in the traffic store

#### Scenario: Replay respects pacing
- **GIVEN** a replay is issued
- **WHEN** the request goes out
- **THEN** it SHALL be subject to the pacing floor and User-Agent rotation

