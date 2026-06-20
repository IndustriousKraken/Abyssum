# Annotations Delta

## ADDED Requirements

### Requirement: Notes On Sessions And Findings
The system SHALL let an operator attach one or more freeform notes to a scan session and to
an individual finding within a session, recording each note's author and creation time, and
SHALL persist notes so they survive a process restart.

#### Scenario: Add a note to a session
- **GIVEN** an existing scan session owned by the operator
- **WHEN** the operator adds a note with non-empty content
- **THEN** the note SHALL be stored against that session
- **AND** the stored note SHALL record its author and creation time

#### Scenario: Add a note to a finding
- **GIVEN** a finding belonging to a session owned by the operator
- **WHEN** the operator adds a note to that finding
- **THEN** the note SHALL be stored against that finding
- **AND** the note SHALL be retrievable when the finding's notes are requested

#### Scenario: Empty note is rejected
- **WHEN** the operator attempts to add a note whose content is empty or only whitespace
- **THEN** the system SHALL reject it with a validation error
- **AND** SHALL NOT store a note

#### Scenario: Note references an unknown session
- **WHEN** the operator attempts to add a note to a session that does not exist
- **THEN** the system SHALL report that the session was not found
- **AND** SHALL NOT store a note

### Requirement: Edit And Delete Notes
The system SHALL let the owner of a note's session edit a note's content and delete a note.

#### Scenario: Edit a note
- **GIVEN** a stored note on a session owned by the operator
- **WHEN** the operator edits the note with new non-empty content
- **THEN** the note's content SHALL be updated
- **AND** the note SHALL record that it was edited

#### Scenario: Editing to empty content is rejected
- **GIVEN** a stored note
- **WHEN** the operator edits it to empty or whitespace-only content
- **THEN** the system SHALL reject the edit with a validation error
- **AND** the note's existing content SHALL be unchanged

#### Scenario: Delete a note
- **GIVEN** a stored note
- **WHEN** the operator deletes it
- **THEN** the note SHALL no longer be retrievable
- **AND** other notes on the same session SHALL be unaffected

### Requirement: Color-Coded Tags
The system SHALL let an operator create reusable tags, each with a unique normalized name, a
color, and an optional description, and SHALL prevent duplicate or malformed tags.

#### Scenario: Create a tag
- **WHEN** the operator creates a tag with a name and a valid color
- **THEN** the tag SHALL be stored and available to apply to sessions

#### Scenario: Duplicate tag name is rejected
- **GIVEN** a tag already exists whose normalized name matches a requested name
- **WHEN** the operator attempts to create another tag with that name
- **THEN** the system SHALL reject it as a duplicate
- **AND** SHALL NOT create a second tag

#### Scenario: Names are normalized before comparison
- **GIVEN** a tag exists under a given name
- **WHEN** the operator references the same name with different letter case or surrounding whitespace
- **THEN** the system SHALL treat it as the same tag
- **AND** SHALL NOT create a duplicate

#### Scenario: Invalid color is rejected
- **WHEN** the operator creates a tag with a color that is not a valid hex color value
- **THEN** the system SHALL reject it with a validation error
- **AND** SHALL NOT create the tag

### Requirement: Apply And Remove Tags On Sessions
The system SHALL let an operator apply one or more tags to a scan session and remove a tag
from a session, where applying a tag by a name that does not yet exist creates that tag.

#### Scenario: Apply existing tags to a session
- **GIVEN** one or more existing tags and a session owned by the operator
- **WHEN** the operator applies those tags to the session
- **THEN** the session SHALL carry those tags

#### Scenario: Applying an unknown tag name creates the tag
- **GIVEN** no tag exists with a requested name
- **WHEN** the operator applies that name to a session
- **THEN** the system SHALL create the tag
- **AND** SHALL apply it to the session

#### Scenario: Re-applying a tag does not duplicate it
- **GIVEN** a session already carries a tag
- **WHEN** the operator applies the same tag again
- **THEN** the session SHALL still carry that tag exactly once

#### Scenario: Remove a tag from a session
- **GIVEN** a session that carries a tag
- **WHEN** the operator removes that tag from the session
- **THEN** the session SHALL no longer carry that tag
- **AND** the tag SHALL still exist for use on other sessions

### Requirement: List Tags With Usage
The system SHALL list all tags, reporting for each tag how many sessions it is applied to.

#### Scenario: List tags with usage counts
- **GIVEN** tags applied across several sessions
- **WHEN** the operator lists all tags
- **THEN** each tag SHALL be returned with the number of sessions it is applied to

### Requirement: Search Sessions By Note Content
The system SHALL let an operator find sessions by matching a search term against note
content, returning the sessions whose notes contain the term.

#### Scenario: Substring match on note content
- **GIVEN** sessions with notes, some containing a search term
- **WHEN** the operator searches by that term
- **THEN** the system SHALL return the sessions whose notes contain the term
- **AND** SHALL NOT return sessions with no matching note

### Requirement: Filter Sessions By Tags
The system SHALL let an operator filter sessions by one or more tags, choosing whether a
session must carry all of the named tags or any of them.

#### Scenario: Match any of the named tags
- **GIVEN** sessions carrying different combinations of tags
- **WHEN** the operator filters by several tags requesting an any-match
- **THEN** the system SHALL return every session carrying at least one of those tags

#### Scenario: Match all of the named tags
- **GIVEN** sessions carrying different combinations of tags
- **WHEN** the operator filters by several tags requesting an all-match
- **THEN** the system SHALL return only sessions carrying every one of those tags

### Requirement: Annotation Ownership And Visibility
The system SHALL scope notes, tag applications, and annotation searches to the requester's
own sessions, while permitting an operator holding the `admin` role to act across all
sessions.

#### Scenario: Non-owner is denied
- **GIVEN** a session owned by another operator
- **WHEN** a non-admin operator attempts to read or modify that session's notes or tags
- **THEN** the system SHALL deny the operation

#### Scenario: Owner may annotate
- **GIVEN** a session owned by the operator
- **WHEN** the operator reads or modifies its notes or tags
- **THEN** the system SHALL permit the operation

#### Scenario: Search is scoped to the owner
- **GIVEN** sessions owned by different operators
- **WHEN** a non-admin operator searches by note content or filters by tags
- **THEN** the results SHALL include only that operator's own sessions

#### Scenario: Admin acts across owners
- **GIVEN** sessions owned by several operators
- **WHEN** an `admin` searches by note content or filters by tags
- **THEN** the results MAY include sessions across all owners

### Requirement: Annotations Cleaned Up With Their Parent
The system SHALL remove a session's notes and tag applications when the session is deleted,
and remove a finding's notes when the finding is deleted, without deleting the shared tag
definitions themselves.

#### Scenario: Deleting a session removes its annotations
- **GIVEN** a session with notes and applied tags
- **WHEN** the session is deleted
- **THEN** the session's notes SHALL be removed
- **AND** its tag applications SHALL be removed
- **AND** the tag definitions SHALL remain available for other sessions
