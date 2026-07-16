# observing-proxy

## ADDED Requirements

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
