# surface-mapping

## ADDED Requirements

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
