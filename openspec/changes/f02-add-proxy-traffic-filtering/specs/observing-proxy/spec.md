# observing-proxy

## ADDED Requirements

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
