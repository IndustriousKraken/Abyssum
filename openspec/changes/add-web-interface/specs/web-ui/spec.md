# Web UI Delta

## ADDED Requirements

### Requirement: Authenticated Web Surface
The web interface SHALL require an authenticated session for every page and data endpoint
except the login page and static assets, so that no scanning or history is reachable
anonymously.

#### Scenario: Unauthenticated page request redirects to login
- **GIVEN** a visitor with no authenticated session
- **WHEN** they request any application page other than the login page
- **THEN** the system SHALL redirect them to the login page
- **AND** SHALL NOT disclose any scan data

#### Scenario: Unauthenticated data request rejected
- **GIVEN** a request to a data or progress endpoint with no authenticated session
- **WHEN** the request is received
- **THEN** the system SHALL reject it as unauthorized
- **AND** SHALL NOT perform the requested action

#### Scenario: Authenticated request succeeds
- **GIVEN** a visitor with a valid authenticated session
- **WHEN** they request an application page
- **THEN** the system SHALL serve the page

### Requirement: Start A Scan From The Web
An authenticated operator SHALL be able to start a scan by choosing one or more targets and
one or more scanners, and the system SHALL create a scan session owned by that operator and
begin executing it.

#### Scenario: Start a scan with valid selections
- **GIVEN** an authenticated operator who supplies at least one target and at least one
  known scanner id
- **WHEN** they submit the scan
- **THEN** the system SHALL create a scan session owned by that operator
- **AND** SHALL begin executing the scan in the background
- **AND** SHALL return the new session identifier so the operator can watch its progress

#### Scenario: Reject a scan with no target or no scanner
- **GIVEN** an authenticated operator
- **WHEN** they submit a scan with no targets, or with no scanners, or naming a scanner id
  that is not registered
- **THEN** the system SHALL reject the request with a clear error
- **AND** SHALL NOT create a scan session

### Requirement: Live Scan Progress Over WebSocket
While a scan runs, the system SHALL deliver live progress for that session to the operator
over a persistent connection, without the operator reloading the page.

#### Scenario: Progress updates stream during a scan
- **GIVEN** an authenticated operator watching a running scan they own
- **WHEN** the scan tests candidates and accumulates findings
- **THEN** the system SHALL push progress updates over the persistent connection
- **AND** each update SHALL convey the current scanner, how many candidates have been tested
  out of the total, and findings discovered so far

#### Scenario: Connecting after progress has begun shows current state
- **GIVEN** a scan already in progress
- **WHEN** the operator opens the live-progress connection for that session
- **THEN** the system SHALL convey the current progress state on the next update
  rather than requiring a page reload

### Requirement: Cancel A Running Scan
An authenticated operator SHALL be able to cancel a running scan they own, and the system
SHALL stop the scan promptly while retaining any findings already discovered.

#### Scenario: Cancel stops the scan and keeps partial findings
- **GIVEN** an authenticated operator with a running scan they own
- **WHEN** they cancel the scan
- **THEN** the system SHALL signal cancellation to the scan engine
- **AND** the scan SHALL stop issuing new requests promptly
- **AND** the findings discovered before cancellation SHALL be retained and remain viewable

### Requirement: Browse Past Sessions And Findings
The system SHALL let an authenticated operator view their past scan sessions and the
findings within each session, including summary statistics.

#### Scenario: Dashboard lists the operator's sessions
- **GIVEN** an authenticated operator with prior scan sessions
- **WHEN** they open the dashboard
- **THEN** the system SHALL list their sessions with summary information
- **AND** SHALL present summary statistics covering their sessions and findings

#### Scenario: Open a session to view its findings
- **GIVEN** an authenticated operator viewing one of their sessions
- **WHEN** they open the session detail
- **THEN** the system SHALL show that session's findings with their evidence

### Requirement: Search And Filter Findings
The system SHALL let an authenticated operator search and filter findings across their
sessions by free text and by structured criteria.

#### Scenario: Filter by structured criteria
- **GIVEN** an authenticated operator with findings across multiple sessions
- **WHEN** they apply any combination of free-text, status, scanner-id, vulnerability-level,
  and target filters
- **THEN** the system SHALL return only the findings that match all supplied criteria

#### Scenario: Free-text search matches finding content
- **GIVEN** an authenticated operator
- **WHEN** they search with a free-text term
- **THEN** the system SHALL return findings whose title or description contains that term
- **AND** SHALL exclude findings that do not

### Requirement: Per-User Visibility With Admin Override
The system SHALL restrict each non-admin operator to viewing and acting on only their own
sessions and findings, while an operator with the admin role SHALL be able to view and act
on all operators' sessions.

#### Scenario: Non-admin cannot see another user's session
- **GIVEN** a session owned by user A
- **AND** an authenticated non-admin user B
- **WHEN** user B lists sessions, searches findings, or requests user A's session detail
- **THEN** the system SHALL NOT include or disclose user A's session to user B

#### Scenario: Non-admin cannot cancel another user's scan
- **GIVEN** a running session owned by user A
- **AND** an authenticated non-admin user B
- **WHEN** user B attempts to cancel that session
- **THEN** the system SHALL deny the request
- **AND** SHALL NOT cancel the scan

#### Scenario: Admin can view and act on any session
- **GIVEN** an authenticated operator with the admin role
- **WHEN** they list sessions or request any session's detail or cancellation
- **THEN** the system SHALL include and act on sessions owned by any user

### Requirement: Custom Requests Tool In The UI
The system SHALL provide an authenticated page where an operator can compose and send an
ad-hoc HTTP request with optional authentication and view the response.

#### Scenario: Send a custom request with authentication
- **GIVEN** an authenticated operator on the custom-requests page
- **WHEN** they submit a request with a target URL, method, optional bearer token, optional
  cookies, and optional custom headers
- **THEN** the system SHALL issue the request as composed
- **AND** SHALL display the response to the operator

#### Scenario: Custom request without credentials is allowed
- **GIVEN** an authenticated operator on the custom-requests page
- **WHEN** they submit a request with no bearer token and no cookies
- **THEN** the system SHALL issue the request without added credentials
- **AND** SHALL display the response
