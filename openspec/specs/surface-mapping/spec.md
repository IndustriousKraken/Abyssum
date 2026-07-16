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

### Requirement: Optional Active Subdomain Brute-Force
The system SHALL support an opt-in active subdomain brute-force discovery source that
generates candidate subdomains from a wordlist and tests each for existence, and this
source SHALL be disabled by default so that reconnaissance stays passive unless the
operator enables it. Candidates confirmed to exist SHALL be evaluated for liveness and
takeover exactly as passively-discovered subdomains are. All existence tests and probes
SHALL pass through the paced request path.

#### Scenario: Brute-force is off by default
- **GIVEN** subdomain reconnaissance with no active brute-force explicitly enabled
- **WHEN** it runs
- **THEN** no wordlist-based brute-force probing SHALL occur

#### Scenario: Enabled brute-force discovers existing subdomains
- **GIVEN** active brute-force is enabled and a wordlist candidate corresponds to a subdomain that exists
- **WHEN** reconnaissance runs
- **THEN** that subdomain SHALL be discovered as a candidate

#### Scenario: Brute-forced candidates are evaluated like passive ones
- **GIVEN** a subdomain discovered by active brute-force
- **WHEN** reconnaissance evaluates it
- **THEN** it SHALL be assessed for liveness and takeover the same way a passively-discovered subdomain is

#### Scenario: Existence tests are paced
- **GIVEN** active brute-force is enabled
- **WHEN** candidates are tested for existence
- **THEN** each test SHALL pass through the paced request path subject to the pacing floor and User-Agent rotation

