# surface-mapping

## ADDED Requirements

### Requirement: Discover Origin IP Behind A CDN Or WAF
The system SHALL attempt to discover the true origin IP of a target that is served
behind a CDN or WAF, gathering candidate IPs from passive sources rather than attacking
the perimeter, and SHALL confirm a candidate by requesting the target host directly
against that IP and comparing the response to the perimeter-served response. A confirmed
origin SHALL be reported as a finding naming the host and origin IP; a candidate that is
not confirmed SHALL NOT be reported as the origin. All lookups and probes SHALL pass
through the paced request path.

#### Scenario: Candidate origins are gathered passively
- **GIVEN** a target fronted by a CDN/WAF
- **WHEN** origin discovery runs
- **THEN** candidate origin IPs SHALL be gathered from passive sources
- **AND** the target's perimeter SHALL NOT be attacked to obtain them

#### Scenario: A confirmed origin is reported
- **GIVEN** a candidate IP that serves the target's content directly when addressed with the target's Host header
- **WHEN** origin discovery evaluates it
- **THEN** it SHALL be reported as the confirmed origin, naming the host and IP

#### Scenario: An unconfirmed candidate is not reported as origin
- **GIVEN** a candidate IP that does not serve the target's content
- **WHEN** origin discovery evaluates it
- **THEN** it SHALL NOT be reported as the origin
