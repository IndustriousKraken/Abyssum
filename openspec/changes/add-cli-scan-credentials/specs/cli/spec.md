# cli

## ADDED Requirements

### Requirement: Authenticated Scans Via Credential Flags
The CLI SHALL accept an optional cookie value and an optional bearer token, and when
either is supplied it SHALL attach the resulting credential to every scanner request
in the scan. Both flags are optional and independent; when neither is supplied the
scan SHALL run without a credential.

#### Scenario: Cookie is attached to scanner requests
- **GIVEN** a scan invoked with a cookie flag
- **WHEN** the scan issues requests to the target
- **THEN** each request SHALL carry the supplied cookie

#### Scenario: Bearer token is attached to scanner requests
- **GIVEN** a scan invoked with a bearer token flag
- **WHEN** the scan issues requests to the target
- **THEN** each request SHALL carry the supplied bearer token

#### Scenario: No credential flag runs unauthenticated
- **GIVEN** a scan invoked with neither a cookie nor a bearer token flag
- **WHEN** the scan issues requests to the target
- **THEN** no credential SHALL be attached to the requests
