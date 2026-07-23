# surface-mapping

## ADDED Requirements

### Requirement: Reconnaissance Stays Within The Target's Apex
The system SHALL only issue requests to hosts that are the target's apex domain or a
subdomain of it. Every candidate host, regardless of the source it came from — passive
discovery, wordlist brute-force, or any future source — SHALL be discarded before any request
is made if it is not within that apex. The number of candidates discarded as out of scope
SHALL be recorded rather than silently ignored.

#### Scenario: A candidate outside the apex is discarded
- **GIVEN** a discovery source returns a name that is not the target's apex or a subdomain of it
- **WHEN** reconnaissance evaluates its candidates
- **THEN** that name SHALL be discarded
- **AND** no request SHALL be issued to it

#### Scenario: A subdomain of the apex is kept
- **GIVEN** a discovered name that is a subdomain of the target's apex
- **WHEN** reconnaissance evaluates its candidates
- **THEN** it SHALL be retained for probing

#### Scenario: Out-of-scope discards are recorded
- **GIVEN** one or more candidates were discarded as outside the apex
- **WHEN** reconnaissance completes
- **THEN** the number discarded SHALL be recorded rather than silently dropped

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
