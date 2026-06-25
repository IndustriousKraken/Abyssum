# IDOR Scan Delta

## ADDED Requirements

### Requirement: Object-Reference Identification

The IDOR scanner SHALL identify object-reference points — endpoint paths that embed an
object identifier and query parameters that carry one — and SHALL establish a baseline
reference for each before probing alternatives.

#### Scenario: Harvests an existing identifier as the baseline

- **GIVEN** a target whose response body exposes an object identifier
- **WHEN** the scanner seeds its references
- **THEN** it SHALL adopt that identifier as a baseline reference of its matching shape
  (numeric, UUID, username, or email)

#### Scenario: Falls back to a default baseline

- **GIVEN** a target that exposes no harvestable identifiers
- **WHEN** the scanner seeds its references
- **THEN** it SHALL use a default baseline reference so enumeration can still proceed

#### Scenario: Probes references other than the baseline

- **GIVEN** an established baseline reference for an object-reference point
- **WHEN** the scanner enumerates that point
- **THEN** it SHALL probe one or more alternative references of the same shape that are not
  the baseline reference

### Requirement: Unauthorized-Access Detection

The scanner SHALL report an insecure direct object reference only when probing a
non-baseline reference, without authorization to that object, returns a successful response
carrying a different object's data.

#### Scenario: Detects access to another object's data

- **GIVEN** a baseline reference whose response is captured
- **WHEN** the scanner requests a different reference without authorization and receives a
  successful response whose body differs materially from the baseline and is not an error
  or not-found page
- **THEN** it SHALL classify the reference as an insecure direct object reference

#### Scenario: Identical response is not a finding

- **GIVEN** a baseline reference whose response is captured
- **WHEN** a different reference returns a response identical to the baseline
- **THEN** it SHALL NOT be reported as an insecure direct object reference

#### Scenario: Error or not-found response is not a finding

- **WHEN** a probed reference returns a not-found, unauthorized, forbidden, or other error
  response
- **THEN** it SHALL NOT be reported as an insecure direct object reference

#### Scenario: Probes without the caller's authorization

- **GIVEN** the scan context carries an authorization credential
- **WHEN** the scanner probes an alternative reference
- **THEN** it SHALL issue that request without the authorization credential so that a
  success demonstrates access that does not depend on the caller's identity

### Requirement: IDOR Finding Reporting

The scanner SHALL report a finding for each confirmed insecure direct object reference,
carrying enough evidence for an operator to reproduce and triage it.

#### Scenario: Finding carries the reference and evidence

- **WHEN** the scanner confirms an insecure direct object reference
- **THEN** it SHALL report a finding that includes the affected endpoint or parameter, the
  reference that was tried, the baseline reference, the observed response status, and a
  bounded sample of the returned data

#### Scenario: Severity reflects exposed-data sensitivity

- **GIVEN** a confirmed insecure direct object reference whose response exposes sensitive
  data such as credentials or personal information
- **WHEN** the finding is recorded
- **THEN** its severity SHALL be raised to reflect the sensitivity of the exposed data

### Requirement: Pacing And Cancellation Compliance

The scanner SHALL issue requests through the shared scan engine so that request pacing,
cancellation, and progress reporting apply uniformly.

#### Scenario: Respects the configured pacing floor

- **GIVEN** a configured minimum delay between requests to a domain
- **WHEN** the scanner probes multiple references on that domain
- **THEN** no request SHALL be issued before the configured minimum delay has elapsed since
  the previous request to that domain

#### Scenario: Stops promptly on cancellation

- **GIVEN** a scan in progress
- **WHEN** the scan is cancelled
- **THEN** the scanner SHALL stop issuing new requests promptly
- **AND** SHALL return the findings discovered so far

#### Scenario: Reports progress

- **WHEN** the scanner enumerates references
- **THEN** it SHALL emit progress updates indicating how many references have been tested
  out of the total

### Requirement: Scanner Registration

The scanner SHALL be registered in the scanner registry under a stable identifier so it can
be selected by the CLI and web surfaces.

#### Scenario: Selectable by id

- **WHEN** a caller requests the scanner with id `idor`
- **THEN** the registry SHALL provide the IDOR scanner
