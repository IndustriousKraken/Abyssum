# authentication Specification

## Purpose
TBD - created by archiving change c02-add-authentication. Update Purpose after archive.
## Requirements
### Requirement: Account Registration With Hashed Passwords
The system SHALL let a user register an account with a username and password, and SHALL
store the password only as a salted password hash, never as plaintext or reversibly
encrypted text.

#### Scenario: Password is never stored in the clear
- **WHEN** a user registers with a username and password
- **THEN** the account SHALL be created
- **AND** the stored credential SHALL be a salted hash that does not equal the submitted
  password

#### Scenario: Same password yields different stored hashes
- **GIVEN** two accounts registered with the same password
- **WHEN** their credentials are stored
- **THEN** the two stored hashes SHALL differ
- **AND** each SHALL still verify against its own password

#### Scenario: Duplicate username is rejected
- **GIVEN** an existing account with a given username
- **WHEN** a registration is attempted with that same username
- **THEN** registration SHALL be rejected with a clear error
- **AND** no second account SHALL be created

### Requirement: Login And Expiring Server-Side Sessions
The system SHALL authenticate a user by verifying the submitted password against the stored
hash and, on success, SHALL establish a server-side session identified by an opaque token
that expires.

#### Scenario: Successful login establishes a session
- **GIVEN** a registered account
- **WHEN** the user logs in with the correct password
- **THEN** the system SHALL establish a session and return an opaque session token

#### Scenario: Invalid credentials are rejected indistinguishably
- **WHEN** a login is attempted with an unknown username
- **OR** with a known username and a wrong password
- **THEN** the login SHALL be rejected
- **AND** the error SHALL NOT reveal which of the username or password was incorrect

#### Scenario: Expired session is no longer valid
- **GIVEN** a session whose expiry time has passed
- **WHEN** that session token is presented
- **THEN** the system SHALL treat the session as invalid
- **AND** SHALL require re-authentication

#### Scenario: Logout ends the session immediately
- **GIVEN** an active session
- **WHEN** the user logs out
- **THEN** the session token SHALL no longer be accepted

### Requirement: Admin Role And First-User Bootstrap
The system SHALL support an `admin` role distinct from a regular user role, and SHALL grant
the `admin` role to the first account registered while granting the regular role to all
subsequent accounts.

#### Scenario: First registered user becomes admin
- **GIVEN** no accounts exist yet
- **WHEN** the first account is registered
- **THEN** that account SHALL have the `admin` role

#### Scenario: Subsequent users are regular users
- **GIVEN** at least one account already exists
- **WHEN** another account is registered
- **THEN** that account SHALL have the regular user role

### Requirement: Scan Session Ownership And Visibility
The system SHALL record the user that created each web-surface scan session as its immutable
owner, and SHALL restrict visibility so a regular user sees only their own sessions while an
`admin` sees all sessions. CLI-initiated sessions have no owner and are visible only to
`admin` users.

#### Scenario: Creating user is recorded as owner
- **GIVEN** an authenticated user starts a scan through the web surface
- **WHEN** the scan session is created
- **THEN** the session SHALL record that user as its owner
- **AND** the owner SHALL NOT change thereafter

#### Scenario: Regular user sees only their own sessions
- **GIVEN** scan sessions owned by different users
- **WHEN** a regular user lists scan sessions
- **THEN** only the sessions that user owns SHALL be returned

#### Scenario: Admin sees all sessions
- **GIVEN** scan sessions owned by different users
- **WHEN** an `admin` user lists scan sessions
- **THEN** sessions owned by every user SHALL be returned

#### Scenario: Non-owner non-admin is denied a session
- **GIVEN** a scan session owned by another user
- **WHEN** a regular user who is not the owner requests that session
- **THEN** the request SHALL be denied

### Requirement: Deny Unauthenticated Access
The system SHALL deny access to protected functionality when the request does not carry a
valid, unexpired session.

#### Scenario: No session token is rejected
- **GIVEN** a request to protected functionality with no session token
- **WHEN** the system evaluates the request
- **THEN** access SHALL be denied

#### Scenario: Invalid or expired session token is rejected
- **GIVEN** a request to protected functionality carrying an unrecognized or expired token
- **WHEN** the system evaluates the request
- **THEN** access SHALL be denied
- **AND** the protected operation SHALL NOT execute

