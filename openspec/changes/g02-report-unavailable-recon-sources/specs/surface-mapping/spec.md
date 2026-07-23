# surface-mapping

## ADDED Requirements

### Requirement: Unavailable Discovery Sources Are Reported
The system SHALL emit an informational finding when an external discovery source it relies on
is unavailable, errors, or returns a non-success response, naming the source and stating that
results may be incomplete, so that an empty result is never indistinguishable from a source
that was never successfully consulted. A source that responds normally SHALL NOT produce such
a finding.

#### Scenario: A failed source is reported
- **GIVEN** an external discovery source that cannot be reached or errors
- **WHEN** reconnaissance runs
- **THEN** an informational finding SHALL be emitted naming the source
- **AND** it SHALL state that results may be incomplete

#### Scenario: A non-success response is reported
- **GIVEN** an external discovery source that returns a non-success status
- **WHEN** reconnaissance runs
- **THEN** an informational finding SHALL be emitted naming the source and its status

#### Scenario: A healthy source is not reported
- **GIVEN** an external discovery source that responds normally
- **WHEN** reconnaissance runs
- **THEN** no source-availability finding SHALL be emitted

#### Scenario: An empty result from a healthy source is distinguishable
- **GIVEN** a source that responds normally but lists no names for the target
- **WHEN** reconnaissance completes
- **THEN** no source-availability finding SHALL be emitted
- **AND** the absence of discovered subdomains SHALL therefore reflect the source's answer rather than a failure to consult it
