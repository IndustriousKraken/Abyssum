# result-persistence

## MODIFIED Requirements

### Requirement: Durable Scan Session Storage
The system SHALL persist each scan session durably, including the id of the user that owns it,
so that a session stored before the process exits is readable, unchanged, after the process
restarts. The owner SHALL be recorded when the session is created and SHALL NOT change
thereafter.

#### Scenario: Session survives a restart
- **GIVEN** a scan session has been stored with its identity, status, target list, selected scanner ids, and owner
- **WHEN** the process restarts and the store is reopened
- **THEN** the session SHALL be retrievable by its identifier
- **AND** its status, target list, scanner ids, and owner SHALL match what was stored

#### Scenario: Re-storing a session updates it in place
- **GIVEN** a session has been stored
- **WHEN** the same session is stored again with an advanced status and updated timing or counts
- **THEN** the existing session SHALL be updated rather than duplicated
- **AND** retrieving the session SHALL return the latest values
- **AND** the recorded owner SHALL remain unchanged
