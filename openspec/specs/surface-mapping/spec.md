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

### Requirement: Discover Origin IP Behind A CDN Or WAF
The system SHALL attempt to discover the true origin IP of a target that is served
behind a CDN or WAF, gathering candidate IPs from passive sources rather than attacking
the perimeter, and SHALL confirm a candidate by requesting the target host directly
against that IP and comparing the response to the perimeter-served response. A confirmed
origin SHALL be reported as a finding naming the host and origin IP; a candidate that is
not confirmed SHALL NOT be reported as the origin. All lookups and probes SHALL pass
through the paced request path.

#### Scenario: Candidate origins are gathered passively
- **GIVEN** a target fronted by a CDN/WAF
- **WHEN** origin discovery runs
- **THEN** candidate origin IPs SHALL be gathered from passive sources
- **AND** the target's perimeter SHALL NOT be attacked to obtain them

#### Scenario: A confirmed origin is reported
- **GIVEN** a candidate IP that serves the target's content directly when addressed with the target's Host header
- **WHEN** origin discovery evaluates it
- **THEN** it SHALL be reported as the confirmed origin, naming the host and IP

#### Scenario: An unconfirmed candidate is not reported as origin
- **GIVEN** a candidate IP that does not serve the target's content
- **WHEN** origin discovery evaluates it
- **THEN** it SHALL NOT be reported as the origin

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

#### Scenario: Source queries are paced
- **GIVEN** enumeration queries a registration-data source
- **WHEN** the query is issued
- **THEN** it SHALL pass through the paced request path subject to the pacing floor and User-Agent rotation

### Requirement: Discover Exposed Cloud Storage Assets
The system SHALL discover candidate cloud-storage assets for a target by generating
candidate names from the target's domain and organization identifiers and probing known
cloud-provider storage endpoints, and SHALL report assets that exist — reporting those
that are publicly readable or listable at high severity as a data-exposure finding. A
candidate that does not exist SHALL NOT be reported. The system SHALL confirm existence
and exposure only, and SHALL NOT download or enumerate asset contents beyond what is
needed to confirm exposure. All probing SHALL pass through the paced request path.

#### Scenario: A publicly listable asset is reported at high severity
- **GIVEN** a candidate that resolves to an existing, publicly readable/listable storage asset
- **WHEN** cloud-asset discovery probes it
- **THEN** it SHALL be reported as a high-severity data-exposure finding

#### Scenario: An existing but access-denied asset is reported as footprint
- **GIVEN** a candidate that exists but returns access-denied
- **WHEN** cloud-asset discovery probes it
- **THEN** it SHALL be reported as an informational finding recording the asset

#### Scenario: A non-existent candidate is not reported
- **GIVEN** a candidate that does not correspond to any asset
- **WHEN** cloud-asset discovery probes it
- **THEN** it SHALL NOT be reported

#### Scenario: Exposure is confirmed without exfiltration
- **GIVEN** a publicly readable asset
- **WHEN** the system confirms its exposure
- **THEN** it SHALL NOT download or enumerate the asset's contents beyond what confirms the exposure

### Requirement: Reconnaissance Stays Within The Target's Apex
The system SHALL, when reconnaissance derives candidate hosts to probe — from passive
discovery, wordlist brute-force, or any future candidate source — retain only those hosts that
are the target's apex domain or a subdomain of it, and SHALL discard every other candidate
before any request is made to it. The number of candidates discarded as out of scope SHALL be
recorded rather than silently ignored. This constraint governs hosts derived from discovery
candidates; it SHALL NOT be read to restrict requests the scanner deliberately directs at a
chosen endpoint — such as probing a cloud-provider storage endpoint for the target's assets —
which remain governed by their own requirements.

#### Scenario: A candidate outside the apex is discarded
- **GIVEN** a discovery source returns a candidate host that is not the target's apex or a subdomain of it
- **WHEN** reconnaissance evaluates its candidates
- **THEN** that candidate SHALL be discarded
- **AND** no request SHALL be issued to it

#### Scenario: A subdomain of the apex is kept
- **GIVEN** a discovered name that is a subdomain of the target's apex
- **WHEN** reconnaissance evaluates its candidates
- **THEN** it SHALL be retained for probing

#### Scenario: Out-of-scope discards are recorded
- **GIVEN** one or more candidates were discarded as outside the apex
- **WHEN** reconnaissance completes
- **THEN** the number discarded SHALL be recorded rather than silently dropped

#### Scenario: A deliberate provider-endpoint probe is not a discovery candidate
- **GIVEN** cloud-asset discovery probes a known cloud-provider storage endpoint for the target's assets
- **WHEN** that request is issued
- **THEN** the apex constraint on discovery candidates SHALL NOT discard it, because it is a deliberately chosen endpoint rather than a discovered host candidate

### Requirement: Candidate Names Cannot Redirect A Request
The system SHALL constrain candidate names to valid DNS labels and SHALL construct each
request so that the candidate determines only the host being requested. A candidate carrying
characters that would otherwise reinterpret a URL's authority — such as those beginning a
path, query, fragment, or userinfo section — SHALL NOT result in a request to any host other
than one within the target's apex.

#### Scenario: A crafted entry cannot change the requested host
- **GIVEN** a wordlist entry containing a character that would terminate a URL's authority
- **WHEN** reconnaissance builds the candidate and its request
- **THEN** the entry SHALL be rejected or sanitized
- **AND** any request that is issued SHALL still be to a host within the target's apex

#### Scenario: Invalid labels are rejected
- **GIVEN** a wordlist entry that is not a valid DNS label
- **WHEN** candidates are generated
- **THEN** that entry SHALL NOT produce a candidate host

#### Scenario: Ordinary labels are unaffected
- **GIVEN** a wordlist entry that is a valid DNS label
- **WHEN** candidates are generated
- **THEN** it SHALL produce the corresponding subdomain of the target's apex

