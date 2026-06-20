# Tasks

## 1. User store and registration
- [ ] 1.1 Add an `auth` module in `abyssum-core` with a `users` table (id, username unique, password_hash, role, created_at) created via the persistence layer
- [ ] 1.2 Implement `register(username, password)` that hashes the password with a fresh random salt and stores only the encoded hash, never plaintext
- [ ] 1.3 Reject registration when the username already exists, returning a clear error
- [ ] 1.4 Assign the `admin` role to the first registered user and the regular `user` role to every subsequent user

## 2. Login, sessions, and logout
- [ ] 2.1 Add an `auth_sessions` table (opaque token, user_id, created_at, expires_at, last_seen_at) — named distinctly from the persistence `sessions` (scan-run) table to avoid collision
- [ ] 2.2 Implement `login(username, password)`: verify the password against the stored hash and, on success, create a session with an opaque high-entropy token and an expiry
- [ ] 2.3 Return an identical, non-revealing error for unknown-username and wrong-password cases
- [ ] 2.4 Implement `authorize(token)` returning the session's user when the token is valid and unexpired, and refreshing the idle timeout
- [ ] 2.5 Treat expired sessions as invalid and implement removal of expired sessions (lazy or swept); read lifetimes from `auth.session_absolute_max_hours` and `auth.session_idle_timeout_minutes` (with sensible defaults)
- [ ] 2.6 Implement `logout(token)` that invalidates the session immediately

## 3. Ownership and visibility
- [ ] 3.1 Add a forward migration adding a nullable `owner_user_id` column to the persistence `sessions` (scan-run) table, and stamp the creating user's id onto each scan session at creation as an immutable owner attribute
- [ ] 3.2 Implement a visibility filter: a regular user may read only sessions they own
- [ ] 3.3 Allow an `admin` user to read all sessions regardless of owner
- [ ] 3.4 Deny any read of a scan session the requesting user is neither owner nor admin for

## 4. Access guard
- [ ] 4.1 Provide a guard that resolves a session token to a user and rejects requests with a missing, invalid, or expired token
- [ ] 4.2 Ensure protected operations (scan and session access) require a valid session before proceeding

## 5. Tests (local only — no real targets)
- [ ] 5.1 Test that a stored password is a hash distinct from the plaintext and that verification accepts the correct password
- [ ] 5.2 Test that registering the same password twice yields different stored hashes (random salt)
- [ ] 5.3 Test first-user-is-admin, subsequent-user-is-regular, and duplicate-username rejection
- [ ] 5.4 Test that wrong-password and unknown-user logins fail with the same error, and correct credentials yield a token
- [ ] 5.5 Test that an expired session is rejected and that logout invalidates a session immediately
- [ ] 5.6 Test ownership/visibility: owner sees own sessions, admin sees all, non-owner non-admin is denied
- [ ] 5.7 Test that protected functionality denies a request with no or an invalid session
