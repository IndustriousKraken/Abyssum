# cors-scan Specification

## Purpose
TBD - created by archiving change b02-add-cors-scanner. Update Purpose after archive.
## Requirements
### Requirement: Crafted-Origin Probing

The CORS scanner SHALL probe a target by issuing requests that carry crafted `Origin`
header values and observing how the server's cross-origin response headers react to each.

#### Scenario: Probes multiple crafted origins

- **GIVEN** a target URL
- **WHEN** the scanner runs against the target
- **THEN** it SHALL send requests carrying, at minimum, an attacker-controlled origin, a
  null origin, and an untrusted origin derived from the target's own domain
- **AND** each request SHALL set its `Origin` header to the crafted value being tested

#### Scenario: Includes credentials when available

- **GIVEN** the scan context carries an authorization credential for the target
- **WHEN** the scanner probes a crafted origin
- **THEN** the probe request SHALL include that credential so credentialed responses are
  exercised

#### Scenario: No cross-origin allowance is not a finding

- **GIVEN** a target whose response omits the `Access-Control-Allow-Origin` header
- **WHEN** the scanner probes a crafted origin
- **THEN** it SHALL NOT report a finding for that origin

#### Scenario: Properly restricted origin is not a finding

- **GIVEN** a target that returns a fixed allowed origin unrelated to the crafted origin
- **WHEN** the scanner probes a crafted attacker origin
- **THEN** it SHALL NOT report a finding for that origin

### Requirement: Permissive CORS Detection

The scanner SHALL report a finding when the server's response indicates a permissive
cross-origin policy, naming the specific misconfiguration observed.

#### Scenario: Reflected arbitrary origin

- **GIVEN** a target that echoes a crafted attacker origin back in
  `Access-Control-Allow-Origin`
- **WHEN** the scanner probes that origin
- **THEN** it SHALL report a finding identifying the misconfiguration as a reflected
  arbitrary origin

#### Scenario: Wildcard combined with credentials

- **GIVEN** a target that returns a wildcard `Access-Control-Allow-Origin`
- **AND** returns `Access-Control-Allow-Credentials` of `true`
- **WHEN** the scanner probes the target
- **THEN** it SHALL report a finding identifying a wildcard-with-credentials
  misconfiguration

#### Scenario: Null origin accepted

- **GIVEN** a target that returns `Access-Control-Allow-Origin` of `null` in response to a
  null-origin probe
- **WHEN** the scanner probes the null origin
- **THEN** it SHALL report a finding identifying acceptance of the null origin

#### Scenario: Untrusted look-alike origin trusted

- **GIVEN** a target that reflects an untrusted origin which merely contains the target's
  domain as a substring
- **WHEN** the scanner probes that look-alike origin
- **THEN** it SHALL report a finding identifying that an untrusted origin is trusted

#### Scenario: Bare wildcard without credentials

- **GIVEN** a target that returns a wildcard `Access-Control-Allow-Origin`
- **AND** does not allow credentials
- **WHEN** the scanner probes the target
- **THEN** it SHALL report a finding identifying a bare wildcard allowance

### Requirement: Finding Evidence

Every CORS finding SHALL carry reproduction evidence so an operator can verify the
misconfiguration by hand.

#### Scenario: Finding records request and response evidence

- **GIVEN** the scanner reports a CORS misconfiguration
- **WHEN** the finding is recorded
- **THEN** it SHALL include the `Origin` value that was sent
- **AND** it SHALL include the returned `Access-Control-Allow-Origin` value
- **AND** it SHALL include the returned `Access-Control-Allow-Credentials` value
- **AND** it SHALL include the probed URL

### Requirement: Severity Reflects Exploitability

The scanner SHALL assign each finding a severity that reflects how exploitable the
misconfiguration is, ranking credentialed cross-origin exposure above the equivalent
misconfiguration without credentials.

#### Scenario: Credentialed reflection is high severity

- **GIVEN** a target that reflects a crafted attacker origin
- **AND** also allows credentials
- **WHEN** the scanner reports the finding
- **THEN** the finding's severity SHALL be higher than that of an equivalent reflection
  where credentials are not allowed

#### Scenario: Bare wildcard is low severity

- **GIVEN** a target that returns a wildcard allowance without credentials
- **WHEN** the scanner reports the finding
- **THEN** the finding's severity SHALL be lower than that of a credentialed reflection

### Requirement: Registration In Scanner Registry

The scanner SHALL be registered under the stable id `cors` so the CLI and web surfaces can
select and run it.

#### Scenario: Selectable by id

- **WHEN** a caller requests the scanner registered under the id `cors`
- **THEN** the registry SHALL provide the CORS scanner

### Requirement: Pacing And Cancellation Compliance

The scanner SHALL issue its probes through the shared scan engine so that request pacing,
cancellation, and progress reporting apply uniformly.

#### Scenario: Respects the configured pacing floor

- **GIVEN** a configured minimum delay between requests to a domain
- **WHEN** the scanner probes multiple crafted origins on that domain
- **THEN** no request SHALL be issued before the configured minimum delay has elapsed since
  the previous request to that domain

#### Scenario: Stops promptly on cancellation

- **GIVEN** a scan in progress
- **WHEN** the scan is cancelled
- **THEN** the scanner SHALL stop issuing new requests promptly
- **AND** SHALL return the findings discovered so far

#### Scenario: Reports progress

- **WHEN** the scanner probes crafted origins
- **THEN** it SHALL emit progress updates indicating how many origins have been tested out
  of the total

