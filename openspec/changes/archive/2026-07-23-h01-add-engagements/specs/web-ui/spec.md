# web-ui

## ADDED Requirements

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
