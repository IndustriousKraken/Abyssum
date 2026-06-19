# Seed Data Delta

## ADDED Requirements

### Requirement: Curated Reference Data In The Database
The system SHALL store its curated reference data — per-scanner wordlists and the
User-Agent pool — in the database, so the data is queryable and extensible at runtime rather
than fixed in the binary.

#### Scenario: Wordlists are retrievable by scanner
- **GIVEN** the reference-data store has been populated
- **WHEN** a scanner requests its wordlist by scanner id
- **THEN** the system SHALL return the curated entries for that scanner

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

### Requirement: Scanners Source Wordlists From The Store
The system SHALL have scanners obtain their candidate paths and queries from the seeded
reference-data store, so probing and the curated data share one source.

#### Scenario: Scanner uses seeded entries
- **GIVEN** a seeded wordlist for a scanner
- **WHEN** that scanner runs
- **THEN** the candidates it probes SHALL come from the seeded wordlist

#### Scenario: Missing wordlist is handled gracefully
- **GIVEN** a scanner whose wordlist is absent from the store
- **WHEN** that scanner runs
- **THEN** the system SHALL report no candidates to probe rather than failing abnormally

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
