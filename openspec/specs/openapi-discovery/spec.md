# openapi-discovery Specification

## Purpose
TBD - created by archiving change b01-add-openapi-discovery-scanner. Update Purpose after archive.
## Requirements
### Requirement: OpenAPI Spec Document Discovery
The OpenAPI discovery scanner SHALL probe a target's base URL against a curated set of
common OpenAPI/Swagger document locations and report a finding when a valid spec document
is served. The set of candidate locations SHALL be loaded from the seeded reference-data
store via named lookup (using the list named `openapi-discovery-paths`), so that the
curated paths share one authoritative source with other scanners. A lookup that returns no
entries SHALL result in zero probes rather than a failure.

#### Scenario: Discovers a published spec document
- **GIVEN** a target that serves an OpenAPI or Swagger document at one of the candidate
  locations
- **WHEN** the scanner runs against the target
- **THEN** it SHALL report a finding for the discovered spec
- **AND** the finding SHALL include the location at which the spec was found and the
  detected spec type

#### Scenario: No spec exposed
- **GIVEN** a target that serves no spec document at any candidate location
- **WHEN** the scanner runs
- **THEN** it SHALL NOT report a discovered spec

### Requirement: Spec Validation Distinguishes Real Documents
The scanner SHALL treat a candidate response as a spec only when its body is a genuine
OpenAPI/Swagger document, so that unrelated successful responses are not reported.

#### Scenario: Genuine spec is accepted
- **GIVEN** a candidate location returns a successful response whose body is a valid
  OpenAPI or Swagger document
- **WHEN** the scanner evaluates the response
- **THEN** it SHALL classify the response as a spec
- **AND** SHALL report it as a discovered spec

#### Scenario: Unrelated successful response is rejected
- **GIVEN** a candidate location returns a successful response whose body is not an
  OpenAPI/Swagger document (for example an unrelated data payload or an HTML page)
- **WHEN** the scanner evaluates the response
- **THEN** it SHALL NOT classify it as a spec
- **AND** SHALL NOT report it as a discovered spec

#### Scenario: Non-success response is ignored
- **GIVEN** a candidate location returns a not-found or error response
- **WHEN** the scanner evaluates the response
- **THEN** it SHALL NOT report a discovered spec for that location

### Requirement: Endpoint Extraction From Discovered Spec
When a valid spec is discovered the scanner SHALL extract the documented endpoints and
structure and include them in the finding as evidence.

#### Scenario: Documented endpoints become evidence
- **GIVEN** a discovered spec that documents one or more API paths
- **WHEN** the scanner reports the finding
- **THEN** the finding evidence SHALL list the documented endpoints that have not already been attributed to a prior finding's evidence
- **AND** each documented path SHALL be expressed relative to the target base URL

#### Scenario: Endpoints de-duplicated across specs
- **GIVEN** more than one valid spec is discovered on the target documenting an overlapping
  path
- **WHEN** the scanner reports findings
- **THEN** the overlapping endpoint SHALL appear in the evidence of at most one finding

### Requirement: Pacing And Cancellation Compliance
The scanner SHALL issue requests through the shared scan engine so that request pacing,
cancellation, and progress reporting apply uniformly.

#### Scenario: Respects the configured pacing floor
- **GIVEN** a configured minimum delay between requests to a domain
- **WHEN** the scanner probes multiple candidate locations on that domain
- **THEN** no request SHALL be issued before the configured minimum delay has elapsed since
  the previous request to that domain

#### Scenario: Stops promptly on cancellation
- **GIVEN** a scan in progress
- **WHEN** the scan is cancelled
- **THEN** the scanner SHALL stop issuing new requests promptly
- **AND** SHALL return the findings discovered so far

#### Scenario: Reports progress
- **WHEN** the scanner probes candidate locations
- **THEN** it SHALL emit progress updates indicating how many candidates have been tested
  out of the total

