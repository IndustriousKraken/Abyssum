# bac-scan Specification

## Purpose
TBD - created by archiving change b03-add-bac-scanner. Update Purpose after archive.
## Requirements
### Requirement: Unauthenticated Probing Of Sensitive Endpoints
The BAC scanner SHALL probe a target's base URL against a curated set of administrative and
sensitive endpoint paths, issuing every probe with any authorization credentials removed so
that a positive result reflects access available without authentication.

#### Scenario: Probes are sent without credentials
- **GIVEN** a scan configured with an authorization credential for the target
- **WHEN** the scanner probes a sensitive path
- **THEN** the issued request SHALL NOT carry that authorization credential

#### Scenario: Each sensitive path is probed
- **GIVEN** a curated set of sensitive paths
- **WHEN** the scanner runs against a target
- **THEN** it SHALL issue an unauthenticated probe for each path in the set

### Requirement: Unauthorized Access Detection
The scanner SHALL report a finding when an unauthenticated probe indicates that a protected
or administrative endpoint is reachable or returns sensitive content, and SHALL NOT report
endpoints that are properly protected or absent.

#### Scenario: Sensitive content exposed without authentication
- **GIVEN** a sensitive path that returns a success response containing sensitive content
  when requested without credentials
- **WHEN** the scanner evaluates the response
- **THEN** it SHALL report a finding for that endpoint
- **AND** the finding SHALL include the endpoint, the observed HTTP status, and evidence of
  the sensitive content observed

#### Scenario: Admin endpoint reachable without authentication
- **GIVEN** an administrative or sensitive-named endpoint that returns a success response
  when requested without credentials
- **WHEN** the scanner evaluates the response
- **THEN** it SHALL report a finding indicating the endpoint is reachable unauthenticated
- **AND** the finding SHALL include the endpoint and the observed HTTP status

#### Scenario: Properly protected endpoint is not a finding
- **GIVEN** a sensitive path that returns an authentication-or-authorization-required
  response when requested without credentials
- **WHEN** the scanner evaluates the response
- **THEN** it SHALL NOT report a finding for that endpoint

#### Scenario: Absent endpoint is not a finding
- **GIVEN** a sensitive path that returns a not-found response
- **WHEN** the scanner evaluates the response
- **THEN** it SHALL NOT report a finding for that endpoint

#### Scenario: Recognized error page is not a finding
- **GIVEN** a sensitive path that returns a success status whose body is a recognized
  not-found or generic error page
- **WHEN** the scanner evaluates the response
- **THEN** it SHALL classify the path as not exposed
- **AND** SHALL NOT report it as unauthorized access

### Requirement: Severity Reflects Exposure
The scanner SHALL assign each finding a severity that reflects the sensitivity of the
endpoint and the class of data exposed, so an operator can triage the most serious
exposures first.

#### Scenario: Sensitive data on an admin endpoint is most severe
- **GIVEN** an administrative endpoint reachable unauthenticated that returns sensitive
  content such as credentials or database details
- **WHEN** the scanner assigns severity
- **THEN** the finding SHALL carry the highest severity

#### Scenario: Reachable admin endpoint without obvious data is medium
- **GIVEN** an administrative or sensitive-named endpoint reachable unauthenticated with no
  obvious sensitive content in the response
- **WHEN** the scanner assigns severity
- **THEN** the finding SHALL carry a medium severity

### Requirement: Sensitive Redirect Follow-Through
The scanner SHALL, when a sensitive path redirects to another sensitive location, follow the
redirect once and evaluate whether the redirect target is itself reachable unauthenticated,
so that a redirect does not conceal an exposed endpoint.

#### Scenario: Redirect target reachable without authentication
- **GIVEN** a sensitive path that redirects to a sensitive location
- **AND** that location returns sensitive or administrative content when requested without
  credentials
- **WHEN** the scanner follows the redirect
- **THEN** it SHALL report a finding for the redirect target
- **AND** the finding SHALL include the redirect target and the observed status

#### Scenario: Redirect target requires authentication
- **GIVEN** a sensitive path that redirects to a sensitive location
- **AND** that location returns an authentication-or-authorization-required response when
  requested without credentials
- **WHEN** the scanner follows the redirect
- **THEN** it SHALL NOT report a finding for the redirect target

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
- **WHEN** the scanner probes sensitive paths
- **THEN** it SHALL emit progress updates indicating how many candidates have been tested
  out of the total

