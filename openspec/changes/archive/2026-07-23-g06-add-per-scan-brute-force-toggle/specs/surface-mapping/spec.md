# surface-mapping

## ADDED Requirements

### Requirement: Active Subdomain Brute-Force Is Selectable Per Scan
The operator SHALL be able to enable the opt-in active subdomain brute-force for a specific
scan, defaulting to off, so it can be used on one scan without changing global configuration.
When it is enabled for a scan, that scan's subdomain reconnaissance SHALL perform the active
brute-force; when it is not, that scan SHALL remain passive.

#### Scenario: Enabling per scan runs brute-force for that scan
- **GIVEN** a scan for which active subdomain brute-force is enabled
- **WHEN** subdomain reconnaissance runs for that scan
- **THEN** it SHALL perform the active brute-force

#### Scenario: Default is off
- **GIVEN** a scan for which active subdomain brute-force is not enabled
- **WHEN** subdomain reconnaissance runs for that scan
- **THEN** it SHALL remain passive and perform no brute-force

#### Scenario: The choice is per scan
- **GIVEN** two scans, one with brute-force enabled and one without
- **WHEN** each runs
- **THEN** the enabled scan SHALL brute-force and the other SHALL not, independently of each other
