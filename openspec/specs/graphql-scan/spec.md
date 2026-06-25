# graphql-scan Specification

## Purpose
TBD - created by archiving change b05-add-graphql-scanner. Update Purpose after archive.
## Requirements
### Requirement: GraphQL Endpoint Detection
The GraphQL scanner SHALL probe a target's base URL against a curated set of common GraphQL
paths and identify which path, if any, serves a GraphQL endpoint.

#### Scenario: Detects a GraphQL endpoint
- **GIVEN** a target that serves a GraphQL endpoint at a path in the candidate set
- **WHEN** the scanner runs against the target
- **THEN** it SHALL identify that path as a GraphQL endpoint
- **AND** it SHALL use the first detected endpoint for the subsequent exposure checks

#### Scenario: Recognizes GraphQL by response shape
- **GIVEN** a candidate path that responds with GraphQL-style content (a body carrying a data
  or errors field, or a GraphQL error message)
- **WHEN** the scanner probes that path
- **THEN** it SHALL classify the path as a GraphQL endpoint

#### Scenario: No GraphQL endpoint present
- **GIVEN** a target that returns not-found or non-GraphQL responses for every candidate path
- **WHEN** the scanner runs
- **THEN** it SHALL report no GraphQL endpoint and no findings

### Requirement: Introspection Exposure Detection
The scanner SHALL send an introspection query to a detected GraphQL endpoint and report a
finding when the server returns schema data.

#### Scenario: Introspection is enabled
- **GIVEN** a detected GraphQL endpoint that answers an introspection query with schema data
- **WHEN** the scanner tests introspection
- **THEN** it SHALL report a finding that introspection is exposed
- **AND** the finding SHALL be rated at least high severity

#### Scenario: Introspection is disabled
- **GIVEN** a detected GraphQL endpoint that does not return schema data for an introspection
  query
- **WHEN** the scanner tests introspection
- **THEN** it SHALL NOT report an introspection finding

### Requirement: Schema Extraction As Evidence
When introspection is exposed, the scanner SHALL extract schema information from the response
and attach it to the finding as evidence.

#### Scenario: Schema details captured
- **GIVEN** an introspection response containing the schema
- **WHEN** the scanner records the introspection finding
- **THEN** the evidence SHALL include the count of types and the names of query and mutation
  fields exposed by the schema

#### Scenario: Sensitive types flagged
- **GIVEN** an introspected schema that defines types whose names suggest sensitive data such
  as users, admins, passwords, or tokens
- **WHEN** the scanner extracts the schema
- **THEN** the evidence SHALL list those types as sensitive

### Requirement: Additional GraphQL Exposure Checks
The scanner SHALL probe a detected GraphQL endpoint for unbounded query depth, query
batching, and sensitive-data disclosure, reporting each exposure it finds as its own finding.

#### Scenario: Unbounded query depth
- **GIVEN** a GraphQL endpoint that accepts and resolves a deeply nested query
- **WHEN** the scanner tests query depth
- **THEN** it SHALL report a finding that the endpoint accepts unbounded query nesting

#### Scenario: Query batching enabled
- **GIVEN** a GraphQL endpoint that answers a batch of queries sent as an array with an
  equal-length array of results
- **WHEN** the scanner tests batching
- **THEN** it SHALL report a finding that query batching is enabled

#### Scenario: Sensitive data disclosed
- **GIVEN** a GraphQL endpoint that returns data containing sensitive field names or values
  such as passwords, tokens, or email addresses
- **WHEN** the scanner runs a sensitive-data query
- **THEN** it SHALL report an information-disclosure finding identifying the exposed data

#### Scenario: Severity reflects exposure
- **GIVEN** multiple GraphQL findings of differing severity on one endpoint
- **WHEN** the scanner summarizes the scan
- **THEN** the overall severity SHALL be the highest severity among the findings

### Requirement: Pacing And Cancellation Compliance
The scanner SHALL issue all requests through the shared scan engine so that request pacing,
cancellation, and progress reporting apply uniformly across both detection and exposure
checks.

#### Scenario: Respects the configured pacing floor
- **GIVEN** a configured minimum delay between requests to a domain
- **WHEN** the scanner probes candidate paths and exposure checks on that domain
- **THEN** no request SHALL be issued before the configured minimum delay has elapsed since
  the previous request to that domain

#### Scenario: Stops promptly on cancellation
- **GIVEN** a scan in progress
- **WHEN** the scan is cancelled
- **THEN** the scanner SHALL stop issuing new requests promptly
- **AND** SHALL return the findings discovered so far

#### Scenario: Reports progress
- **WHEN** the scanner probes candidate paths and runs exposure checks
- **THEN** it SHALL emit progress updates indicating how many items have been tested out of
  the total

