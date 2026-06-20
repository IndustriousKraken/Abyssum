# seed-data Specification

## Purpose
TBD - created by archiving change a04-add-seed-data. Update Purpose after archive.
## Requirements
### Requirement: Curated Reference Data In The Database
The system SHALL store its curated reference data — per-scanner wordlists and the
User-Agent pool — in the database, so the data is queryable and extensible at runtime rather
than fixed in the binary.

#### Scenario: Wordlists are retrievable by name
- **GIVEN** the reference-data store has been populated
- **WHEN** a named wordlist is requested
- **THEN** the system SHALL return that list's curated entries in their seeded order

#### Scenario: A scanner can load more than one named list
- **GIVEN** a scanner that draws on multiple named wordlists
- **WHEN** it requests each of its lists by name
- **THEN** the system SHALL return each requested list independently

#### Scenario: Labeled entries retain a label and a body
- **GIVEN** a seeded list whose entries each carry a label and a body (such as named GraphQL probe queries)
- **WHEN** that list is retrieved
- **THEN** each entry SHALL expose both its label and its body

#### Scenario: User-Agent pool is present
- **GIVEN** the reference-data store has been populated
- **WHEN** the system requests the available User-Agents
- **THEN** it SHALL return the seeded pool, each entry marked as realistic or not

### Requirement: Idempotent First-Run Seeding
The system SHALL seed the reference-data store from its bundled assets when the store is
empty, and SHALL be safe to run repeatedly without creating duplicate entries.

#### Scenario: Empty store is seeded
- **GIVEN** a database whose reference-data store is empty
- **WHEN** the system starts
- **THEN** it SHALL populate the store from the bundled wordlists and User-Agent pool

#### Scenario: Re-seeding does not duplicate
- **GIVEN** a store that has already been seeded
- **WHEN** seeding runs again
- **THEN** the entry counts SHALL be unchanged
- **AND** no duplicate entries SHALL be created

### Requirement: Named Lookup Is The Single Source For Candidates
The system SHALL provide scanners their candidate paths and queries solely through named
lookups against the seeded reference-data store, so probing and the curated data share one
source. A lookup for a list that is absent SHALL return no candidates rather than failing.

#### Scenario: Named lookup returns the seeded entries
- **GIVEN** a seeded wordlist
- **WHEN** the list is looked up by its name
- **THEN** the lookup SHALL return exactly the seeded entries for that list

#### Scenario: Missing wordlist is handled gracefully
- **GIVEN** a lookup for a list name that is not present in the store
- **WHEN** the lookup runs
- **THEN** it SHALL return no candidates rather than failing abnormally

### Requirement: Realistic Rotating User-Agent By Default
The system SHALL, by default, present outbound scan requests with a realistic
(browser or mobile) User-Agent drawn from the pool and varied across requests, and SHALL NOT
use a scanner-announcing User-Agent unless one is explicitly selected. This upholds the
stealth posture: ordinary traffic that does not trip basic intrusion detection.

#### Scenario: Default requests blend in
- **GIVEN** no explicit User-Agent override
- **WHEN** the system issues scan requests
- **THEN** each request's User-Agent SHALL be one of the realistic entries from the pool
- **AND** SHALL NOT be a scanner-announcing identity

#### Scenario: User-Agent varies across requests
- **GIVEN** no explicit User-Agent override
- **WHEN** the system issues many scan requests
- **THEN** the User-Agent presented SHALL NOT be identical for every request

#### Scenario: Explicit opt-in to a specific identity
- **GIVEN** the operator explicitly selects a specific User-Agent
- **WHEN** the system issues scan requests
- **THEN** it SHALL use the selected User-Agent

