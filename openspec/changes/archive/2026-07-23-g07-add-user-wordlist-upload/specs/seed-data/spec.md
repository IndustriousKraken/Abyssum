# seed-data

## MODIFIED Requirements

### Requirement: Named Lookup Is The Single Source For Candidates
The system SHALL provide scanners their candidate paths and queries solely through named
lookups against the reference-data store, so probing and the curated data share one source. A
named lookup SHALL return the entries of the named list — by default the seeded list, or an
operator-provided custom list when one has been selected for the current scan. A lookup for a
list that is absent SHALL return no candidates rather than failing.

#### Scenario: Named lookup returns the seeded entries by default
- **GIVEN** a seeded wordlist and no custom list selected for the scan
- **WHEN** the list is looked up by its name
- **THEN** the lookup SHALL return exactly the seeded entries for that list

#### Scenario: Named lookup returns a selected custom list
- **GIVEN** an operator has selected a custom wordlist for the scan
- **WHEN** the corresponding list is looked up by its name
- **THEN** the lookup SHALL return the entries of that selected custom list

#### Scenario: Missing wordlist is handled gracefully
- **GIVEN** a lookup for a list name that is not present in the store
- **WHEN** the lookup runs
- **THEN** it SHALL return no candidates rather than failing abnormally
