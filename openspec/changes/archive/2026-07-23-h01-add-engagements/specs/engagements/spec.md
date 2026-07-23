# engagements

## ADDED Requirements

### Requirement: An Engagement Organizes Scans Under An Authorization
The system SHALL let an operator create an engagement — a named grouping under which scans are
organized and the job's authorization is recorded — and SHALL record the creating operator as
its owner together with the time it was created. A scan session MAY be associated with at most
one engagement, and that association SHALL record which operator made it. An engagement and its
scan associations SHALL be persisted durably so they survive a process restart.

#### Scenario: An engagement is created and persisted
- **GIVEN** an operator creates an engagement with a name
- **WHEN** the engagement is stored
- **THEN** the system SHALL record the engagement with its name, its creating operator as owner, and its creation time
- **AND** the engagement SHALL remain retrievable after a process restart

#### Scenario: A scan is associated with an engagement
- **GIVEN** an existing engagement and a scan session
- **WHEN** an operator associates the scan with the engagement
- **THEN** the session SHALL belong to that one engagement
- **AND** the association SHALL record which operator made it

#### Scenario: A scan belongs to at most one engagement
- **GIVEN** a scan session already associated with an engagement
- **WHEN** it is associated with a different engagement
- **THEN** the session SHALL belong only to the most recently chosen engagement, not to several at once

#### Scenario: A scan need not belong to an engagement
- **GIVEN** a scan started without choosing an engagement
- **WHEN** it runs and is stored
- **THEN** it SHALL be a valid unassociated session, exactly as scans are today

### Requirement: An Engagement Holds Scope And Authorization Documents
The system SHALL let an operator attach one or more scope or authorization documents to an
engagement, each provided as pasted text, an external URL, or an uploaded file, so the
engagement's scope and proof of authorization sit alongside its scans for reference. Each
document SHALL record which operator added it and when. Uploaded files SHALL be limited to a
bounded set of document types and a bounded size, and an upload exceeding those bounds SHALL be
rejected with a clear error rather than stored or truncated. Attached documents SHALL be
persisted durably so they survive a process restart.

#### Scenario: Pasted scope text is attached
- **GIVEN** an operator viewing an engagement
- **WHEN** they attach scope text pasted from a bug-bounty program
- **THEN** the system SHALL store it as a document of that engagement, recording the operator who added it and when
- **AND** it SHALL remain retrievable after a process restart

#### Scenario: A link to a scope document is attached
- **GIVEN** an operator viewing an engagement
- **WHEN** they attach an external URL pointing at a program or contract scope
- **THEN** the system SHALL store the URL as a document of that engagement

#### Scenario: A signed authorization file is uploaded
- **GIVEN** an operator viewing an engagement
- **WHEN** they upload a file of an allowed document type within the size limit
- **THEN** the system SHALL store the file as a document of that engagement, recording the operator who added it

#### Scenario: An oversized or disallowed upload is rejected
- **GIVEN** an operator uploading a file that exceeds the size limit or is not an allowed document type
- **WHEN** the upload is submitted
- **THEN** the system SHALL reject it with a clear error
- **AND** SHALL NOT store it

### Requirement: A Stored Scope Is Operator Reference Only
The system SHALL treat an engagement's scope and authorization documents as reference material
for the operator only, and SHALL NOT interpret their content to constrain, expand, or otherwise
alter what any scan targets or how any scanner behaves. Associating a scan with an engagement
SHALL NOT change the scan's targets, selected scanners, or pacing.

#### Scenario: Attaching scope does not change scanning
- **GIVEN** an engagement with an attached scope document
- **WHEN** a scan associated with that engagement runs
- **THEN** the scan's targets, scanners, and pacing SHALL be exactly those it was started with
- **AND** the stored scope content SHALL NOT add, remove, or restrict any target or scanner
