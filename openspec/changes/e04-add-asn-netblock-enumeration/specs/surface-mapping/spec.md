# surface-mapping

## ADDED Requirements

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
