# result-persistence Specification

## Purpose
TBD - created by archiving change a03-add-result-persistence. Update Purpose after archive.
## Requirements
### Requirement: Durable Scan Session Storage
The system SHALL persist each scan session durably so that a session stored before the
process exits is readable, unchanged, after the process restarts.

#### Scenario: Session survives a restart
- **GIVEN** a scan session has been stored with its identity, status, target list, and selected scanner ids
- **WHEN** the process restarts and the store is reopened
- **THEN** the session SHALL be retrievable by its identifier
- **AND** its status, target list, and scanner ids SHALL match what was stored

#### Scenario: Re-storing a session updates it in place
- **GIVEN** a session has been stored
- **WHEN** the same session is stored again with an advanced status and updated timing or counts
- **THEN** the existing session SHALL be updated rather than duplicated
- **AND** retrieving the session SHALL return the latest values

### Requirement: Durable Finding Storage
The system SHALL persist each finding under its scan session, retaining the full canonical
finding shape — scanner id, target, status classification, severity, title, description,
evidence, and remediation guidance — so that a finding stored before the process exits is
readable, unchanged, after the process restarts. The stored status SHALL be one of the shared
status values and the stored severity SHALL be one of the shared severity levels.

#### Scenario: Finding retains its fields across a restart
- **GIVEN** a finding has been stored for a session with a scanner id, target, status, severity, title, description, evidence, and remediation guidance
- **WHEN** the process restarts and the finding is retrieved
- **THEN** all of those fields SHALL match what was stored

#### Scenario: Stored finding has a stable identifier
- **GIVEN** a finding is stored under a session
- **WHEN** it is stored
- **THEN** the system SHALL assign it a stable identifier that uniquely addresses that finding
- **AND** the identifier SHALL remain unchanged across retrieval and restart

#### Scenario: Findings are linked to their session
- **GIVEN** several findings have been stored under one session
- **WHEN** that session's findings are requested
- **THEN** exactly those findings SHALL be returned
- **AND** findings belonging to other sessions SHALL NOT be included

### Requirement: Query Sessions
The system SHALL allow stored sessions to be retrieved individually and listed in a
predictable order with paging.

#### Scenario: Retrieve a session with its findings
- **WHEN** a session is requested by its identifier
- **THEN** the system SHALL return the session together with its stored findings
- **AND** SHALL return nothing when no session has that identifier

#### Scenario: List sessions newest-first with paging
- **GIVEN** more sessions exist than a requested page size
- **WHEN** sessions are listed with a limit and an offset
- **THEN** the system SHALL return at most the limit number of sessions
- **AND** SHALL order them most-recently-created first

### Requirement: Filter Findings
The system SHALL allow stored findings to be filtered by status, severity, scanner id, target,
a date range, and a free-text query over the finding's title and description, and SHALL allow
these filters to be combined.

#### Scenario: Filter by free-text query
- **GIVEN** stored findings whose titles and descriptions contain differing text
- **WHEN** findings are queried with a free-text query
- **THEN** only findings whose title or description matches the query SHALL be returned

#### Scenario: Filter by severity
- **GIVEN** stored findings with differing severity levels
- **WHEN** findings are queried filtered by a severity level
- **THEN** only findings with that severity SHALL be returned

#### Scenario: Filter by status
- **GIVEN** stored findings with differing status classifications
- **WHEN** findings are queried filtered by one status
- **THEN** only findings with that status SHALL be returned

#### Scenario: Filter by scanner id
- **GIVEN** stored findings produced by different scanners
- **WHEN** findings are queried filtered by a scanner id
- **THEN** only findings produced by that scanner SHALL be returned

#### Scenario: Filter by target
- **GIVEN** stored findings against different targets
- **WHEN** findings are queried filtered by a target
- **THEN** only findings against that target SHALL be returned

#### Scenario: Filter by date range
- **GIVEN** stored findings recorded at different times
- **WHEN** findings are queried with a start and end date
- **THEN** only findings recorded within that range SHALL be returned

#### Scenario: Combined filters narrow the result
- **GIVEN** stored findings spanning several statuses, scanners, and targets
- **WHEN** findings are queried with more than one filter applied together
- **THEN** only findings matching all applied filters SHALL be returned

### Requirement: Summary Counts
The system SHALL report summary counts over stored data — the number of sessions, the number
of findings, and a breakdown of findings by severity — so a surface can present statistics
without loading every record. The counts SHALL be restrictable to a supplied subset of
sessions, so a surface can present owner-scoped statistics by supplying that owner's sessions
(this keeps the store itself ownership-blind).

#### Scenario: Counts summarize stored data
- **GIVEN** stored sessions and findings of differing severities
- **WHEN** summary counts are requested
- **THEN** the system SHALL report the total number of sessions and findings
- **AND** SHALL report how many findings fall under each severity level

#### Scenario: Counts restricted to a subset of sessions
- **GIVEN** stored findings spread across several sessions
- **WHEN** summary counts are requested restricted to a subset of those sessions
- **THEN** only findings belonging to that subset SHALL be counted

### Requirement: Delete A Session And Its Findings
The system SHALL delete a session together with all of its findings as a single atomic
operation, leaving no orphaned findings.

#### Scenario: Deleting a session removes its findings
- **GIVEN** a stored session with findings
- **WHEN** the session is deleted
- **THEN** the session SHALL no longer be retrievable
- **AND** none of its findings SHALL remain
- **AND** other sessions and their findings SHALL be unaffected

### Requirement: Schema Initialization And Migration
The system SHALL create its storage schema on first use and apply forward migrations on
later startups, upgrading an existing store in place rather than discarding stored data.

#### Scenario: First-run initialization
- **GIVEN** no storage exists at the configured location
- **WHEN** the system starts
- **THEN** it SHALL create the storage and its schema
- **AND** sessions and findings SHALL be storable immediately afterward

#### Scenario: Reopening an existing store preserves data
- **GIVEN** a store that already contains sessions and findings
- **WHEN** the system starts again against that store
- **THEN** previously stored sessions and findings SHALL remain intact
- **AND** applying any pending schema changes SHALL NOT discard existing data

