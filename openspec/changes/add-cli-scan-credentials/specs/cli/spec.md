# cli

## ADDED Requirements

### Requirement: Authenticated Scans Via Credential Flags
The CLI SHALL accept an optional cookie value and an optional bearer token, and when
either is supplied it SHALL make the resulting credential available to each scanner
via the scan context. Scanners whose contract requires credentialed requests SHALL
include the credential; scanners whose contract requires unauthenticated probes
(e.g. BAC, IDOR) SHALL omit it. Both flags are optional and independent; when neither
is supplied the scan SHALL run without a credential.

#### Scenario: Cookie is made available to scanners
- **GIVEN** a scan invoked with a cookie flag
- **WHEN** the scan issues requests to the target
- **THEN** the cookie SHALL be available via the scan context, and scanners that require credentialed requests SHALL include it

#### Scenario: Bearer token is made available to scanners
- **GIVEN** a scan invoked with a bearer token flag
- **WHEN** the scan issues requests to the target
- **THEN** the bearer token SHALL be available via the scan context, and scanners that require credentialed requests SHALL include it

#### Scenario: No credential flag runs unauthenticated
- **GIVEN** a scan invoked with neither a cookie nor a bearer token flag
- **WHEN** the scan issues requests to the target
- **THEN** no credential SHALL be available in the scan context
