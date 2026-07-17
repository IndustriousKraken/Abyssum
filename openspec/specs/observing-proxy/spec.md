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

