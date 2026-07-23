# surface-mapping

## MODIFIED Requirements

### Requirement: Discover Subdomains From Passive Sources
The system SHALL discover subdomains of a target apex domain by querying passive
certificate-transparency and/or passive-DNS sources, and SHALL NOT brute-force the
target's own DNS in doing so. Every source query SHALL be issued through the shared
paced request path as a support-infrastructure lookup, so User-Agent rotation applies and
pacing follows the support-infrastructure policy rather than the target pacing floor.

#### Scenario: Subdomains gathered from a passive source
- **GIVEN** an apex domain with known subdomains recorded in a passive source
- **WHEN** subdomain reconnaissance runs
- **THEN** those subdomains SHALL be collected as candidates

#### Scenario: Discovery does not brute-force target DNS
- **GIVEN** an apex domain
- **WHEN** subdomain reconnaissance runs
- **THEN** candidates SHALL come from passive sources
- **AND** the system SHALL NOT enumerate the target's DNS by brute force in this pass

#### Scenario: Source queries are paced as support infrastructure
- **GIVEN** a passive source is queried
- **WHEN** the query is issued
- **THEN** it SHALL pass through the paced request path as a support-infrastructure lookup, with User-Agent rotation

### Requirement: Optional Active Subdomain Brute-Force
The system SHALL support an opt-in active subdomain brute-force discovery source that
generates candidate subdomains from a wordlist and tests each for existence by querying a
public DNS resolver — a request sent to the resolver, not directly to the target — and this
source SHALL be disabled by default so that reconnaissance stays passive unless the
operator enables it. Candidates confirmed to exist SHALL be evaluated for liveness and
takeover exactly as passively-discovered subdomains are. The existence-test queries to the
resolver are support-infrastructure lookups; the subsequent liveness and takeover probes are
sent to the discovered hosts and are target traffic. All SHALL pass through the paced request
path.

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

#### Scenario: Existence tests are paced as support infrastructure
- **GIVEN** active brute-force is enabled
- **WHEN** candidates are tested for existence
- **THEN** each existence test SHALL pass through the paced request path as a support-infrastructure lookup, with User-Agent rotation

### Requirement: Enumerate ASN And Netblocks
The system SHALL, given a target domain or IP, enumerate the autonomous system number
(ASN) and the IP netblocks associated with the owning organization using registration-
data sources such as RDAP or WHOIS, and SHALL report the discovered ASN and netblocks.
The system SHALL perform enumeration only: it SHALL NOT manipulate routing or perform any
BGP action. All source queries SHALL pass through the paced request path.

#### Scenario: ASN and netblocks are enumerated
- **GIVEN** a target domain or IP whose owner has a registered ASN and netblocks
- **WHEN** enumeration runs
- **THEN** the ASN and its associated netblocks SHALL be reported, naming the owning organization

#### Scenario: Enumeration performs no routing action
- **GIVEN** an enumeration run
- **WHEN** it queries registration-data sources
- **THEN** it SHALL NOT manipulate routing or perform any BGP action

#### Scenario: Source queries are paced as support infrastructure
- **GIVEN** enumeration queries a registration-data source
- **WHEN** the query is issued
- **THEN** it SHALL pass through the paced request path as a support-infrastructure lookup, with User-Agent rotation
