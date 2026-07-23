# web-ui Specification

## Purpose
TBD - created by archiving change c03-add-web-interface. Update Purpose after archive.
## Requirements
### Requirement: Authenticated Web Surface
The web interface SHALL require an authenticated session for every page and data endpoint
except the login page, the registration page, and static assets, so that no scanning or
history is reachable anonymously.

#### Scenario: Unauthenticated page request redirects to login
- **GIVEN** a visitor with no authenticated session
- **WHEN** they request any application page other than the login page or the registration page
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

### Requirement: Register An Operator Account
The web interface SHALL provide a public registration page through which an operator can
create a local account, so the first operator can bootstrap the instance and obtain the admin
role. Registration SHALL create the account through the authentication engine, applying the
first-user-becomes-admin rule.

#### Scenario: First operator registers and becomes admin
- **GIVEN** an instance with no accounts yet
- **WHEN** a visitor submits the registration form with a username and password
- **THEN** the system SHALL create the account with the admin role
- **AND** SHALL direct the operator to log in

#### Scenario: Duplicate username is rejected at registration
- **GIVEN** an account with a given username already exists
- **WHEN** a visitor submits the registration form with that same username
- **THEN** the system SHALL reject the registration with a clear error
- **AND** SHALL NOT create a second account

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

### Requirement: Manage Engagements From The Web
The web interface SHALL let an authenticated operator create an engagement, list the engagements
they are authorized for, open one to view its associated scans and attached documents, associate
a scan with an engagement when starting it or afterward, and attach scope or authorization
documents to it as pasted text, an external URL, or an uploaded file.

#### Scenario: Create and open an engagement
- **GIVEN** an authenticated operator
- **WHEN** they create an engagement with a name and later open it
- **THEN** the system SHALL show the engagement with its associated scans and attached documents

#### Scenario: Associate a scan with an engagement
- **GIVEN** an authenticated operator with an engagement
- **WHEN** they choose that engagement while starting a scan, or assign an existing scan to it
- **THEN** the created or existing session SHALL be associated with that engagement
- **AND** the scan SHALL run exactly as it would without the association

#### Scenario: Attach a scope document through the UI
- **GIVEN** an authenticated operator viewing an engagement they may edit
- **WHEN** they paste scope text, supply a scope URL, or upload an allowed document
- **THEN** the system SHALL attach it to the engagement for later reference

### Requirement: Safely Serve And Render Scope Documents
The web interface SHALL serve and render an engagement's attached documents without allowing
their operator-supplied, untrusted content to execute in the application's context. An uploaded
document SHALL be served with its intended document content type and with content-type sniffing
disabled, and SHALL NOT be served as active content in the application's origin. Pasted scope
text SHALL be shown as text, a scope URL SHALL be presented as a link the operator follows
deliberately, and an uploaded PDF SHALL be rendered inline using the browser's native viewer
without loading any external code.

#### Scenario: An uploaded document cannot execute as page content
- **GIVEN** an operator has uploaded a document whose bytes could be interpreted as HTML or script
- **WHEN** another authorized operator views it
- **THEN** the system SHALL serve it with a fixed document content type and content-type sniffing disabled
- **AND** it SHALL NOT execute in the application's origin

#### Scenario: A PDF is rendered inline for reference
- **GIVEN** an engagement with an uploaded PDF authorization document
- **WHEN** an authorized operator opens it
- **THEN** the system SHALL render it inline using the browser's native PDF viewer
- **AND** SHALL NOT require loading code from outside the application to display it

#### Scenario: Pasted text and links are shown as themselves
- **GIVEN** an engagement with pasted scope text and a scope URL
- **WHEN** an authorized operator views the engagement
- **THEN** the pasted text SHALL be shown as text and the URL SHALL be shown as a link

### Requirement: Per-User Visibility Of Engagements
The system SHALL restrict each non-admin operator to viewing and acting on only the engagements
they are authorized for — today, the engagements they created — while an operator with the admin
role SHALL be able to view and act on all engagements. The set of operators authorized for an
engagement SHALL be recorded per engagement so it can widen later without changing this rule.

#### Scenario: Non-admin cannot see another operator's engagement
- **GIVEN** an engagement created by operator A
- **AND** an authenticated non-admin operator B who is not authorized for it
- **WHEN** operator B lists engagements or requests that engagement's detail or documents
- **THEN** the system SHALL NOT include or disclose it to operator B

#### Scenario: Admin can view any engagement
- **GIVEN** an authenticated operator with the admin role
- **WHEN** they list engagements or open any engagement's detail
- **THEN** the system SHALL include and act on engagements created by any operator

#### Scenario: Authorization is recorded per engagement
- **GIVEN** an engagement
- **WHEN** the system records who may view and act on it
- **THEN** that authorization SHALL be stored with the engagement as a set of operators
- **AND** today that set SHALL be exactly its creator

### Requirement: Engagement Results Rollup
The web interface SHALL present, on an engagement's detail view, a rollup of the results across
the scans associated with that engagement — a breakdown of findings by severity together with the
findings aggregated across those scans — so an operator sees the engagement's results in one place
without opening each scan. The rollup SHALL include only sessions associated with the engagement
that the operator is already permitted to see under the existing per-user visibility rule: a
non-admin operator's rollup covers only their own sessions within the engagement, while an
operator with the admin role sees all of the engagement's sessions. The rollup SHALL NOT disclose
any session or finding the operator could not already view.

#### Scenario: Rollup summarizes the operator's findings across the engagement's scans
- **GIVEN** an engagement with several associated scans the operator owns, which have produced findings
- **WHEN** the operator opens the engagement's detail view
- **THEN** the system SHALL show a breakdown of those findings by severity
- **AND** SHALL present the findings aggregated across the operator's scans associated with the engagement

#### Scenario: Rollup covers only the engagement's sessions
- **GIVEN** findings spread across sessions associated with the engagement and other sessions that are not
- **WHEN** the rollup is shown
- **THEN** it SHALL count and present only findings from sessions associated with that engagement
- **AND** SHALL NOT include findings from other engagements or from unassociated sessions

#### Scenario: Rollup does not widen per-user visibility
- **GIVEN** an engagement whose associated sessions include one owned by a different operator
- **AND** an authenticated non-admin operator viewing that engagement
- **WHEN** the rollup is shown
- **THEN** it SHALL NOT include the other operator's session or its findings
- **AND** an operator with the admin role viewing the same engagement SHALL see all of its associated sessions in the rollup

