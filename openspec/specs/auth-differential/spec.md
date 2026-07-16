# auth-differential Specification

## Purpose
TBD - created by archiving change add-auth-differential-scan. Update Purpose after archive.
## Requirements
### Requirement: Scan A Surface Under Multiple Identities
The system SHALL accept two or more named identities for a scan, each being either
anonymous (no credential) or a credential consisting of a cookie and/or a bearer
token, and SHALL run the selected scanners against the targets once per identity. Every
request issued for every identity SHALL flow through the shared request path so that
the configured pacing floor and User-Agent rotation apply to each identity's pass.

#### Scenario: Each identity scans the surface
- **GIVEN** a scan configured with two identities
- **WHEN** the scan runs against a target
- **THEN** the selected scanners SHALL execute once for each identity
- **AND** each identity's requests SHALL carry that identity's credential (or none, if anonymous)

#### Scenario: Pacing applies to every identity
- **GIVEN** a scan configured with multiple identities
- **WHEN** the identities' passes issue requests to the same host
- **THEN** every request SHALL be subject to the configured pacing floor and User-Agent rotation
- **AND** no identity SHALL bypass the pacing floor

### Requirement: Report Access-Control Divergence Across Identities
The system SHALL emit a finding when a resource that should be scoped to one identity
is reachable by another identity that should not have access, naming the resource and
the identities that could access it. A resource that is properly scoped — served only
to the identity that owns it, and denied or differing for others — SHALL NOT produce a
finding.

#### Scenario: Cross-identity access is reported
- **GIVEN** a resource that belongs to one identity
- **WHEN** a different identity retrieves the same resource with equivalent privileged content
- **THEN** the system SHALL emit a finding naming the resource and the identities that could access it

#### Scenario: Anonymous access to a privileged endpoint is reported
- **GIVEN** an endpoint intended to require authentication
- **WHEN** the anonymous identity reaches it successfully
- **THEN** the system SHALL emit a finding

#### Scenario: Properly scoped resource produces no finding
- **GIVEN** a resource served only to its owning identity and denied or differing for others
- **WHEN** the differential comparison runs
- **THEN** no finding SHALL be emitted for that resource

