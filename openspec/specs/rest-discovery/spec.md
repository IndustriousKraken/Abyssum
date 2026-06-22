# rest-discovery Specification

## Purpose
TBD - created by archiving change b00-add-rest-discovery-scanner. Update Purpose after archive.
## Requirements
### Requirement: Wordlist-Based Endpoint Discovery
The REST discovery scanner SHALL probe a target's base URL against a curated set of
candidate endpoint paths and report which paths correspond to existing endpoints.

#### Scenario: Discovers an existing endpoint
- **GIVEN** a target that serves an API endpoint at a path in the candidate set
- **WHEN** the scanner runs against the target
- **THEN** it SHALL report a finding for that path
- **AND** the finding SHALL include the path and the observed HTTP status

#### Scenario: Ignores non-existent paths
- **GIVEN** a target that returns a not-found response for a candidate path
- **WHEN** the scanner runs
- **THEN** it SHALL NOT report a finding for that path

#### Scenario: Soft-404 is not a finding
- **GIVEN** a target that returns a 2xx status with a not-found body for unknown paths
- **WHEN** the scanner probes an unknown path
- **THEN** it SHALL classify the path as absent
- **AND** SHALL NOT report it as a discovered endpoint

### Requirement: Finding Classification
The scanner SHALL classify each discovered endpoint by accessibility so an operator can
distinguish openly accessible endpoints from protected ones.

#### Scenario: Accessible endpoint
- **GIVEN** a candidate path returns an accessible API response
- **WHEN** the scanner classifies it
- **THEN** the finding SHALL indicate the endpoint is accessible

#### Scenario: Protected endpoint
- **GIVEN** a candidate path returns an authentication-or-authorization-required response
- **WHEN** the scanner classifies it
- **THEN** the finding SHALL indicate the endpoint exists but is protected

### Requirement: Pacing And Cancellation Compliance
The scanner SHALL issue requests through the shared scan engine so that request pacing,
cancellation, and progress reporting apply uniformly.

#### Scenario: Respects the configured pacing floor
- **GIVEN** a configured minimum delay between requests to a domain
- **WHEN** the scanner probes multiple paths on that domain
- **THEN** no request SHALL be issued before the configured minimum delay has elapsed since
  the previous request to that domain

#### Scenario: Stops promptly on cancellation
- **GIVEN** a scan in progress
- **WHEN** the scan is cancelled
- **THEN** the scanner SHALL stop issuing new requests promptly
- **AND** SHALL return the findings discovered so far

#### Scenario: Reports progress
- **WHEN** the scanner probes candidate paths
- **THEN** it SHALL emit progress updates indicating how many candidates have been tested
  out of the total

