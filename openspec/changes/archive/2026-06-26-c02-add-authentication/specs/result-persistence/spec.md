# result-persistence

## MODIFIED Requirements

### Requirement: Durable Scan Session Storage
The system SHALL persist each scan session durably — including, where present, the id of the
user that owns it — so that a session stored before the process exits is readable, unchanged,
after the process restarts. The owner field is nullable: sessions created through the
authenticated web surface SHALL record the creating user as owner; CLI-initiated sessions
have no owner. When set, the owner SHALL be recorded at session creation and SHALL NOT change
thereafter.

#### Scenario: Session survives a restart
- **GIVEN** a scan session has been stored with its identity, status, target list, selected scanner ids, and owner (if set)
- **WHEN** the process restarts and the store is reopened
- **THEN** the session SHALL be retrievable by its identifier
- **AND** its status, target list, scanner ids, and owner (if set) SHALL match what was stored

#### Scenario: Re-storing a session updates it in place
- **GIVEN** a session has been stored
- **WHEN** the same session is stored again with an advanced status and updated timing or counts
- **THEN** the existing session SHALL be updated rather than duplicated
- **AND** retrieving the session SHALL return the latest values
- **AND** the recorded owner (if set) SHALL remain unchanged
