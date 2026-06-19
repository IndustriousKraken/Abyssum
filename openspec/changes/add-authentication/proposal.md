## Why

The v2 instance is **multi-user with authentication** (see `openspec/project.md` locked
decisions). The web UI is specified as living entirely behind auth, and scan sessions are
**owned by the creating user** so a small team can share one instance without seeing each
other's findings. None of this existed in v1, so it is greenfield — grounded in the canon's
"Multi-user + auth" decision and the Open Questions defaults rather than mined Python.

This change establishes local accounts, securely hashed passwords, expiring server-side
sessions, an `admin` role, and the **ownership/visibility** rule for scan sessions. It
depends on `bootstrap-rust-workspace` (config, error model, persistence wiring) and on
`add-result-persistence` (the scan-session records this change attributes to an owner).

This capability deliberately **owns** scan-session ownership and visibility;
`add-result-persistence` stores sessions and findings but does not decide who may see them.

## What Changes

### 1. Account registration with hashed passwords

A user registers with a username and password. Passwords are stored **only** as a salted
password hash — never plaintext, never reversibly encrypted. A duplicate username is
rejected.

### 2. Login and expiring server-side sessions

A user logs in with their credentials; on success the system establishes a **server-side
session** keyed by an opaque session token. Sessions **expire** after an idle/absolute
lifetime and can be explicitly ended by logout. Bad credentials are rejected without
revealing whether the username or the password was wrong.

### 3. Admin role and first-user bootstrap

There is an `admin` role and a regular user role. The **first** account to register becomes
admin (first-registered-user-becomes-admin — canon-default open question, flagged as an
assumption); every subsequent account is a regular user.

### 4. Scan-session ownership and visibility

Every scan session records the user that created it. A regular user may view **only their
own** sessions; an `admin` may view **all** sessions (owner-only + admin-sees-all — canon
default, flagged as an assumption). The ownership stamp is set at creation and is immutable.

### 5. Deny unauthenticated access to protected functionality

Any request to protected functionality without a valid, unexpired session is **denied**.
Authentication is required before any scan operation or session data can be reached.

## Impact

- Adds the `authentication` capability to `openspec/specs/`.
- Consumes `add-result-persistence`: scan-session records gain an immutable owner attribute
  and visibility is filtered by the rules defined here.
- Unblocks `add-web-interface` (#14), which is specified as being entirely behind auth.
