# custom-wordlists Specification

## Purpose
TBD - created by archiving change g07-add-user-wordlist-upload. Update Purpose after archive.
## Requirements
### Requirement: Operators Provide Their Own Wordlists
An authenticated operator SHALL be able to provide a wordlist of their own by pasting text or
uploading a text file through the web interface. Such a wordlist SHALL be owned by that
operator and SHALL be visible and selectable only to them.

#### Scenario: A wordlist is imported by paste or upload
- **GIVEN** an authenticated operator with a list of terms
- **WHEN** they paste the text or upload a text file
- **THEN** the terms SHALL be stored as a wordlist owned by that operator

#### Scenario: A wordlist is private to its owner
- **GIVEN** two operators each with their own wordlists
- **WHEN** one operator views the selectable wordlists
- **THEN** the other operator's wordlists SHALL NOT be visible to them

### Requirement: Imported Wordlists Are Normalized And The Import Is Reported
On import the system SHALL normalize entries — trimming whitespace, dropping blank lines and
comments, lowercasing, and removing duplicates — and SHALL report how many entries were
imported and how many were dropped, rather than importing silently.

#### Scenario: Entries are normalized
- **GIVEN** an import containing blank lines, comments, duplicates, and surrounding whitespace
- **WHEN** the list is imported
- **THEN** those entries SHALL be trimmed, de-duplicated, and stripped of blanks and comments

#### Scenario: The import result is reported
- **GIVEN** an import that dropped some lines
- **WHEN** it completes
- **THEN** the operator SHALL be told how many entries were imported and how many were dropped

### Requirement: A Custom Wordlist Is Selectable Per Scan
An operator SHALL be able to select one of their wordlists for a scan; a scanner that consumes
that wordlist SHALL use the selected one for that scan. When no custom wordlist is selected,
the seeded default wordlist SHALL apply.

#### Scenario: The selected wordlist is used
- **GIVEN** a scan for which the operator selected one of their wordlists
- **WHEN** a scanner that uses a wordlist runs for that scan
- **THEN** it SHALL use the selected wordlist

#### Scenario: No selection uses the seeded default
- **GIVEN** a scan with no custom wordlist selected
- **WHEN** a scanner that uses a wordlist runs
- **THEN** it SHALL use the seeded default wordlist

### Requirement: Large Wordlists Are Bounded And Truncation Is Reported
The number of wordlist entries a scan uses SHALL be limited by a configurable bound, and when a
selected wordlist exceeds that bound the truncation SHALL be reported rather than applied
silently.

#### Scenario: A large wordlist is truncated visibly
- **GIVEN** a selected wordlist with more entries than the configured bound
- **WHEN** a scan uses it
- **THEN** only up to the bound SHALL be used
- **AND** the truncation SHALL be reported rather than dropped silently

