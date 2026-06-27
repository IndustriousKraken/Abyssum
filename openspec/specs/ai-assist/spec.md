# ai-assist Specification

## Purpose
TBD - created by archiving change d02-add-ai-assist. Update Purpose after archive.
## Requirements
### Requirement: On-Demand Finding Analysis

The system SHALL, on operator request, send a single stored finding's context to the
configured chat model and return the model's analysis to the operator.

#### Scenario: Analyze a finding and return the model's text

- **GIVEN** a stored finding with a scanner id, target, status classification, severity, and evidence
- **AND** a reachable, configured chat provider
- **WHEN** the operator requests AI analysis of that finding
- **THEN** the system SHALL send the finding's context to the provider
- **AND** SHALL return the model's textual analysis to the operator

#### Scenario: Analysis is grounded in the finding's evidence

- **GIVEN** a stored finding carrying specific evidence
- **WHEN** AI analysis is requested for it
- **THEN** the request sent to the provider SHALL include that finding's scanner id, target, status, severity, and evidence

#### Scenario: Request frames the work as authorized analysis

- **GIVEN** a stored finding
- **WHEN** AI analysis is requested for it
- **THEN** the request SHALL include a system message framing the task as analysis of authorized security testing
- **AND** the finding's details SHALL be carried in a separate user message

#### Scenario: Oversized evidence is truncated, not rejected

- **GIVEN** a stored finding whose evidence exceeds the request size limit
- **WHEN** AI analysis is requested for it
- **THEN** the system SHALL truncate the evidence before sending
- **AND** SHALL still complete the analysis request

### Requirement: Configurable OpenAI-Compatible Provider

The system SHALL select its analysis provider by configuration, identifying any
OpenAI-compatible chat endpoint by a base URL and a model name.

#### Scenario: Provider is taken from configuration

- **GIVEN** a configured base URL and model name for an OpenAI-compatible endpoint
- **WHEN** the operator requests AI analysis
- **THEN** the system SHALL send the request to that base URL using that model

#### Scenario: Changing the configured provider redirects requests

- **GIVEN** the configured base URL and model are changed to a different OpenAI-compatible endpoint
- **WHEN** AI analysis is next requested
- **THEN** the request SHALL be sent to the newly configured endpoint and model

### Requirement: Optional API Key

The system SHALL support an optional API key for the provider; when no key is configured it
SHALL make requests with no credential, and such requests SHALL succeed against endpoints
that require none.

#### Scenario: No key configured sends no credential

- **GIVEN** a configured endpoint that requires no API key
- **AND** no API key is set in configuration or environment
- **WHEN** the operator requests AI analysis
- **THEN** the system SHALL send the request with no authorization credential
- **AND** the request SHALL succeed and return the model's analysis

#### Scenario: Key configured sends a credential

- **GIVEN** an API key is configured
- **WHEN** the operator requests AI analysis
- **THEN** the system SHALL include that key as the request's authorization credential

### Requirement: Best-Effort Non-Fatal AI Calls

The system SHALL treat every AI call as best-effort: any provider error, transport failure,
malformed response, or timeout SHALL surface a clear message to the operator and SHALL NOT
abort the scan, the persistence flow, or any surrounding operation.

#### Scenario: Provider error surfaces a clear message

- **GIVEN** a configured provider that returns an error response
- **WHEN** the operator requests AI analysis
- **THEN** the system SHALL surface a clear message describing the failure
- **AND** SHALL NOT abort any scan or persistence operation in progress

#### Scenario: Timeout surfaces a clear message

- **GIVEN** a configured provider that does not respond within the configured timeout
- **WHEN** the operator requests AI analysis
- **THEN** the system SHALL stop waiting after the timeout
- **AND** SHALL surface a clear timeout message rather than hanging or crashing

#### Scenario: Malformed response is handled gracefully

- **GIVEN** a configured provider that returns a response the system cannot interpret
- **WHEN** the operator requests AI analysis
- **THEN** the system SHALL surface a clear message that the analysis could not be obtained
- **AND** SHALL leave the finding and surrounding flow unchanged

#### Scenario: Disabled or unconfigured AI returns a notice

- **GIVEN** AI assistance is disabled or its provider is not configured
- **WHEN** the operator requests AI analysis
- **THEN** the system SHALL return a clear notice that AI assistance is unavailable
- **AND** SHALL NOT attempt an outbound request

### Requirement: Outbound-Only AI Integration

The system SHALL expose AI assistance as an outbound capability only, providing no inbound
interface for an external agent to drive or control Abyssum.

#### Scenario: Only Abyssum initiates AI calls

- **WHEN** AI assistance is used
- **THEN** the system SHALL act only as the caller of the external chat provider
- **AND** SHALL NOT expose any endpoint, listener, or callback through which an external agent can invoke or control Abyssum

### Requirement: Analysis Surface On A Finding

The system SHALL provide an operator-facing way to request AI analysis of a specific stored
finding from the finding's detail view in the web interface, and SHALL display the returned
analysis or, on a non-fatal failure, a clear notice in its place.

#### Scenario: Operator triggers analysis from a finding

- **GIVEN** an authenticated operator viewing a stored finding they may access
- **WHEN** they invoke the finding's AI-analysis action
- **THEN** the system SHALL request analysis for that finding
- **AND** SHALL display the returned analysis with the finding

#### Scenario: Failure shows a notice in place

- **GIVEN** AI analysis is requested for a finding
- **WHEN** the analysis cannot be obtained (disabled, unconfigured, or a provider failure)
- **THEN** the system SHALL display a clear notice in place of an analysis
- **AND** SHALL leave the finding and the surrounding view unchanged

