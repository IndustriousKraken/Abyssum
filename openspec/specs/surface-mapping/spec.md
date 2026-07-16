# surface-mapping Specification

## Purpose
TBD - created by archiving change e01-add-subdomain-recon. Update Purpose after archive.
## Requirements
### Requirement: Discover Subdomains From Passive Sources
The system SHALL discover subdomains of a target apex domain by querying passive
certificate-transparency and/or passive-DNS sources, and SHALL NOT brute-force the
target's own DNS in doing so. Every source query SHALL be issued through the shared
paced request path, so the configured pacing floor and User-Agent rotation apply.

#### Scenario: Subdomains gathered from a passive source
- **GIVEN** an apex domain with known subdomains recorded in a passive source
- **WHEN** subdomain reconnaissance runs
- **THEN** those subdomains SHALL be collected as candidates

#### Scenario: Discovery does not brute-force target DNS
- **GIVEN** an apex domain
- **WHEN** subdomain reconnaissance runs
- **THEN** candidates SHALL come from passive sources
- **AND** the system SHALL NOT enumerate the target's DNS by brute force in this pass

#### Scenario: Source queries are paced
- **GIVEN** a passive source is queried
- **WHEN** the query is issued
- **THEN** it SHALL pass through the paced request path subject to the pacing floor and User-Agent rotation

### Requirement: Report Live Discovered Subdomains
The system SHALL probe each discovered candidate to determine whether it is live, and
SHALL report each live subdomain as an informational finding recording the discovered
host. A candidate that is not live SHALL NOT be reported as a live subdomain. Probing
SHALL pass through the paced request path.

#### Scenario: Live subdomain is reported
- **GIVEN** a discovered candidate that responds when probed
- **WHEN** reconnaissance evaluates it
- **THEN** it SHALL be reported as a live subdomain in an informational finding

#### Scenario: Dead candidate is not reported as live
- **GIVEN** a discovered candidate that does not respond
- **WHEN** reconnaissance evaluates it
- **THEN** it SHALL NOT be reported as a live subdomain

### Requirement: Detect Subdomain Takeover
The system SHALL flag a discovered subdomain as a takeover candidate when its probe
response matches a known fingerprint of an unclaimed third-party service, emitting a
high-severity vulnerable finding that names the subdomain and the suspected service. A
live subdomain whose response matches no such fingerprint SHALL NOT produce a takeover
finding.

#### Scenario: Takeover fingerprint produces a finding
- **GIVEN** a discovered subdomain whose response matches an unclaimed-service takeover fingerprint
- **WHEN** reconnaissance evaluates it
- **THEN** a vulnerable finding SHALL be emitted naming the subdomain and the suspected service
- **AND** its severity SHALL be high or greater

#### Scenario: Ordinary live subdomain produces no takeover finding
- **GIVEN** a live subdomain whose response matches no takeover fingerprint
- **WHEN** reconnaissance evaluates it
- **THEN** no takeover finding SHALL be emitted for it

