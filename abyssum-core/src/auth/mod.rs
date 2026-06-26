//! Local accounts, password hashing, and expiring server-side sessions.
//!
//! This module is the single authentication authority every surface shares (the
//! web layer in `add-web-interface` consumes it via middleware; this change
//! specifies only the engine-level behavior). It owns three persisted concepts,
//! all in the SQLite store from `add-result-persistence`:
//!
//! - `users` — one row per account: a unique username, an Argon2id password hash
//!   (never plaintext), and a [`Role`].
//! - `auth_sessions` — one row per active login: an opaque high-entropy token,
//!   the owning user, and absolute/idle expiry bookkeeping.
//! - the `owner_user_id` stamp on scan `sessions` — defined and enforced here
//!   (see [`visible_session`] / [`visible_sessions`]).
//!
//! ## Passwords
//!
//! Passwords are hashed with **Argon2id** (the current OWASP default; memory-hard
//! and GPU-resistant) via the `password-hash` traits. The crate generates a fresh
//! per-password salt from `OsRng` and embeds it, together with the algorithm
//! parameters, in the encoded PHC string we store — so two registrations of the
//! same password yield different stored hashes, and we never store a bare hash or
//! manage salts by hand. Verification is constant-time; the login error is
//! identical for an unknown username and a wrong password (and the unknown-user
//! path still runs a verify against a dummy hash so the two are timing-alike too).
//!
//! ## Sessions
//!
//! A login session is bounded by both an **absolute** maximum age (a hard ceiling
//! from creation) and an **idle** timeout (refreshed on each authorized use), both
//! read from the `auth` config section. Server-side storage means a session can be
//! revoked immediately on logout, and an expired one is treated as absent and
//! removed (lazily on access, or in bulk via [`purge_expired`]).
//!
//! [`purge_expired`]: AuthManager::purge_expired

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chrono::{DateTime, Duration, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use sqlx::sqlite::{SqlitePool, SqliteRow};
use sqlx::Row;
use uuid::Uuid;

use crate::config::{AuthConfig, Config};
use crate::error::{db_err, Error, Result};
use crate::persistence::DatabaseManager;
use crate::scan::ScanSession;

/// The single, non-revealing error for any failed login: an unknown username and
/// a wrong password are rejected identically (in message and in timing).
const INVALID_CREDENTIALS: &str = "invalid username or password";

/// The error for an absent, unrecognized, or expired session token.
const INVALID_SESSION: &str = "session is invalid or expired";

/// A 100-year ceiling (in seconds) on any configured session lifetime, so a wild
/// config value can never overflow [`chrono::Duration`] when it is constructed.
const MAX_LIFETIME_SECS: u64 = 100 * 365 * 24 * 3600;

/// The closed set of account roles. `admin` sees every scan session; `user` sees
/// only their own. No per-resource ACLs, teams, or SSO (canon defers those).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Full visibility across all owners; granted to the first registrant.
    Admin,
    /// A regular account; visibility limited to its own sessions.
    User,
}

impl Role {
    /// The on-disk spelling of this role.
    fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::User => "user",
        }
    }

    /// Parse a stored role, rejecting an unknown value as a store error.
    fn parse(text: &str) -> Result<Role> {
        match text {
            "admin" => Ok(Role::Admin),
            "user" => Ok(Role::User),
            other => Err(Error::Database(format!("unknown role in store: {other:?}"))),
        }
    }
}

/// An authenticated account, as resolved from a credential or a session token.
/// Carries no secret — the password hash never leaves the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// Stable primary key; the value stamped onto an owned scan session.
    pub id: i64,
    /// The unique login name.
    pub username: String,
    /// This account's role.
    pub role: Role,
    /// When the account was registered.
    pub created_at: DateTime<Utc>,
}

impl User {
    /// Whether this user holds the `admin` role (sees all sessions).
    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }
}

/// The engine-level authentication authority over the shared SQLite store. Cheap
/// to clone (the pool is reference-counted).
#[derive(Debug, Clone)]
pub struct AuthManager {
    pool: SqlitePool,
    absolute_max: Duration,
    idle_timeout: Duration,
}

impl AuthManager {
    /// Build over an existing pool and the `auth` configuration. The `users` and
    /// `auth_sessions` tables are created by the persistence migration set, so the
    /// pool must already be migrated (it is, after [`DatabaseManager::connect`]).
    pub fn new(pool: SqlitePool, config: &AuthConfig) -> Self {
        Self {
            pool,
            absolute_max: clamp_lifetime(config.session_absolute_max_hours.saturating_mul(3600)),
            idle_timeout: clamp_lifetime(config.session_idle_timeout_minutes.saturating_mul(60)),
        }
    }

    /// Convenience: build over a [`DatabaseManager`]'s pool using the `auth`
    /// section of `config`.
    pub fn from_database(db: &DatabaseManager, config: &Config) -> Self {
        Self::new(db.pool().clone(), &config.auth)
    }

    // --- Registration -----------------------------------------------------

    /// Register an account, storing only a salted Argon2id hash of `password`.
    /// The **first** account registered becomes [`Role::Admin`]; every subsequent
    /// account is a regular [`Role::User`]. A duplicate username is rejected with a
    /// clear [`Error::Auth`] and no second account is created.
    pub async fn register(&self, username: &str, password: &str) -> Result<User> {
        // Hash before opening the transaction — hashing is the slow step and needs
        // no lock. The salt is fresh per call, so the same password registered
        // twice produces different stored hashes.
        let hash = hash_password(password)?;

        // SQLite serializes writers, so inside the transaction the existence check
        // and the first-user role decision are race-free against another register.
        // ponytail: relies on SQLite's single-writer model; no app-level lock.
        let mut tx = self.pool.begin().await.map_err(db_err)?;

        let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = ?")
            .bind(username)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
        if existing > 0 {
            // Dropping `tx` rolls back; no row was written.
            return Err(Error::Auth(format!(
                "username {username:?} is already taken"
            )));
        }

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
        let role = if total == 0 { Role::Admin } else { Role::User };

        // Bind created_at explicitly (RFC-3339) rather than leaning on the column
        // default, so the value we read back later decodes cleanly as DateTime.
        let now = Utc::now();
        let id = sqlx::query(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        )
        .bind(username)
        .bind(&hash)
        .bind(role.as_str())
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?
        .last_insert_rowid();

        tx.commit().await.map_err(db_err)?;

        Ok(User {
            id,
            username: username.to_string(),
            role,
            created_at: now,
        })
    }

    // --- Login / logout ---------------------------------------------------

    /// Verify `password` for `username` and, on success, create a server-side
    /// session and return its opaque token. An unknown username and a wrong
    /// password are rejected identically — same [`Error::Auth`] message, and the
    /// unknown-user path still runs a verify against a dummy hash so the two are
    /// timing-alike, leaking neither which field was wrong nor whether the user
    /// exists.
    pub async fn login(&self, username: &str, password: &str) -> Result<String> {
        let row = sqlx::query(
            "SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        // Always run a verify so the unknown-user path costs the same as a
        // wrong-password one (timing-indistinguishable). For an unknown user the
        // verify runs against a fixed dummy hash and can never succeed.
        let (user, hash) = match row {
            Some(row) => {
                let hash: String = row.try_get("password_hash").map_err(db_err)?;
                (Some(row_to_user(&row)?), hash)
            }
            None => (None, dummy_hash().to_string()),
        };

        match (verify_password(password, &hash), user) {
            (true, Some(user)) => self.create_login_session(user.id).await,
            _ => Err(Error::Auth(INVALID_CREDENTIALS.to_string())),
        }
    }

    /// Invalidate a session immediately. The token is no longer accepted by
    /// [`authorize`](Self::authorize) once this returns. Logging out an unknown or
    /// already-expired token is a no-op (still `Ok`).
    pub async fn logout(&self, token: &str) -> Result<()> {
        self.delete_session(token).await.map(|_| ())
    }

    // --- Authorization ----------------------------------------------------

    /// Resolve a session token to its [`User`], refreshing the idle timeout.
    /// Returns [`Error::Auth`] for an unrecognized token or one past either its
    /// absolute or idle lifetime; an expired session is removed in passing so a
    /// stale row never lingers.
    pub async fn authorize(&self, token: &str) -> Result<User> {
        let row = sqlx::query(
            "SELECT s.expires_at AS expires_at, s.last_seen_at AS last_seen_at, \
                    u.id AS id, u.username AS username, u.role AS role, u.created_at AS created_at \
             FROM auth_sessions s JOIN users u ON u.id = s.user_id \
             WHERE s.token = ?",
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        let Some(row) = row else {
            return Err(Error::Auth(INVALID_SESSION.to_string()));
        };

        let expires_at: DateTime<Utc> = row.try_get("expires_at").map_err(db_err)?;
        let last_seen_at: DateTime<Utc> = row.try_get("last_seen_at").map_err(db_err)?;
        let now = Utc::now();

        // Expired by the absolute ceiling or by idle inactivity -> treat as absent.
        // Remove it (lazy sweep) and require re-authentication.
        if now >= expires_at || now >= last_seen_at + self.idle_timeout {
            self.delete_session(token).await?;
            return Err(Error::Auth(INVALID_SESSION.to_string()));
        }

        // Refresh the idle window on each authorized use.
        sqlx::query("UPDATE auth_sessions SET last_seen_at = ? WHERE token = ?")
            .bind(now)
            .bind(token)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;

        row_to_user(&row)
    }

    /// The access guard a surface calls before any protected operation: resolve an
    /// optional bearer token to the authenticated [`User`], rejecting a missing,
    /// empty, unrecognized, or expired token. The protected operation runs only
    /// when this returns `Ok`.
    pub async fn guard(&self, token: Option<&str>) -> Result<User> {
        match token {
            Some(token) if !token.is_empty() => self.authorize(token).await,
            _ => Err(Error::Auth("authentication required".to_string())),
        }
    }

    /// Delete every session past its absolute or idle lifetime, returning how many
    /// were removed. A periodic complement to the lazy removal in
    /// [`authorize`](Self::authorize).
    pub async fn purge_expired(&self) -> Result<u64> {
        let now = Utc::now();
        let idle_cutoff = now - self.idle_timeout;
        let result =
            sqlx::query("DELETE FROM auth_sessions WHERE expires_at <= ? OR last_seen_at <= ?")
                .bind(now)
                .bind(idle_cutoff)
                .execute(&self.pool)
                .await
                .map_err(db_err)?;
        Ok(result.rows_affected())
    }

    // --- Internals --------------------------------------------------------

    /// Create a session row for `user_id` with a fresh opaque token, an absolute
    /// expiry, and `last_seen_at` set to now (starting the idle window).
    async fn create_login_session(&self, user_id: i64) -> Result<String> {
        let token = new_token();
        let now = Utc::now();
        let expires_at = now + self.absolute_max;
        sqlx::query(
            "INSERT INTO auth_sessions (token, user_id, created_at, expires_at, last_seen_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&token)
        .bind(user_id)
        .bind(now)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(token)
    }

    /// Remove a session by token, returning how many rows were deleted.
    async fn delete_session(&self, token: &str) -> Result<u64> {
        let result = sqlx::query("DELETE FROM auth_sessions WHERE token = ?")
            .bind(token)
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(result.rows_affected())
    }
}

// --- Scan-session visibility (owner-only + admin-sees-all) -----------------

/// List the scan sessions `viewer` may see: only their own for a regular user,
/// every session for an `admin`. Paged like
/// [`DatabaseManager::list_sessions`]. This realizes the canon's "owner-only +
/// admin-sees-all" decision over the persisted `owner_user_id` stamp.
pub async fn visible_sessions(
    db: &DatabaseManager,
    viewer: &User,
    limit: i64,
    offset: i64,
) -> Result<Vec<ScanSession>> {
    if viewer.is_admin() {
        db.list_sessions(limit, offset).await
    } else {
        db.list_sessions_owned_by(viewer.id, limit, offset).await
    }
}

/// Fetch one scan session enforcing visibility: the owner or an `admin` gets it;
/// anyone else is denied with [`Error::Auth`]. A session the viewer may not see —
/// and one that does not exist — both yield an error, never the session.
pub async fn visible_session(
    db: &DatabaseManager,
    viewer: &User,
    session_id: Uuid,
) -> Result<ScanSession> {
    match db.get_session(session_id).await? {
        Some(session) if viewer.is_admin() || session.owner_user_id == Some(viewer.id) => {
            Ok(session)
        }
        Some(_) => Err(Error::Auth(
            "access to this scan session is denied".to_string(),
        )),
        None => Err(Error::Auth("scan session not found".to_string())),
    }
}

// --- Hashing / token helpers -----------------------------------------------

/// Hash `password` with Argon2id and a fresh random salt, returning the encoded
/// PHC string (salt + parameters embedded) to store.
fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| Error::Auth(format!("password hashing failed: {e}")))
}

/// Verify `password` against a stored PHC `encoded` hash, in constant time. A
/// malformed stored hash verifies as `false` rather than erroring.
fn verify_password(password: &str, encoded: &str) -> bool {
    match PasswordHash::new(encoded) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// A fixed Argon2id hash to verify against when the username is unknown, so the
/// login failure path costs the same whether or not the user exists. Hardcoded
/// (not computed) so it has no failure mode that could quietly skip the verify
/// and shorten the unknown-user path. Generated offline with `Argon2::default()`
/// params (`m=4096,t=3,p=1`), which must match what [`hash_password`] emits so
/// the dummy verify costs the same as a real one; the
/// `dummy_hash_uses_default_params` test guards that.
const DUMMY_HASH: &str =
    "$argon2id$v=19$m=4096,t=3,p=1$ra1p8llsgiBhwdjx9qzC0Q$FaAY9lkRGyYfSthvIZcFtecQpQaLm13BGq5F1+Q1sC8";

/// See [`DUMMY_HASH`].
fn dummy_hash() -> &'static str {
    DUMMY_HASH
}

/// A fresh opaque, high-entropy session token: 32 CSPRNG bytes (256 bits),
/// hex-encoded.
fn new_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    to_hex(&bytes)
}

/// Lowercase-hex encode bytes (a token never needs a hex *crate*).
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Clamp a configured lifetime (in seconds) to a sane ceiling and build a
/// [`Duration`], so an extreme config value cannot overflow the conversion.
fn clamp_lifetime(secs: u64) -> Duration {
    Duration::seconds(secs.min(MAX_LIFETIME_SECS) as i64)
}

/// Map a row exposing `id`, `username`, `role`, `created_at` into a [`User`].
fn row_to_user(row: &SqliteRow) -> Result<User> {
    Ok(User {
        id: row.try_get("id").map_err(db_err)?,
        username: row.try_get("username").map_err(db_err)?,
        role: Role::parse(&row.try_get::<String, _>("role").map_err(db_err)?)?,
        created_at: row.try_get("created_at").map_err(db_err)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_hash_uses_default_params() {
        // The dummy must parse, never accidentally verify, and carry the SAME
        // Argon2 params as a real stored hash — otherwise the unknown-user verify
        // would cost differently and weaken the timing equalization. Param drift
        // (e.g. an argon2 crate bump changing the defaults) fails this.
        assert!(
            PasswordHash::new(DUMMY_HASH).is_ok(),
            "dummy must be valid PHC"
        );
        assert!(!verify_password("hunter2", DUMMY_HASH));

        let live = PasswordHash::new(DUMMY_HASH).unwrap();
        let fresh = hash_password("x").unwrap();
        let fresh = PasswordHash::new(&fresh).unwrap();
        assert_eq!(live.algorithm, fresh.algorithm);
        assert_eq!(live.version, fresh.version);
        assert_eq!(
            live.params, fresh.params,
            "DUMMY_HASH params drifted from Argon2::default(); regenerate it"
        );
    }

    #[test]
    fn hash_is_not_plaintext_and_round_trips() {
        let hash = hash_password("hunter2").unwrap();
        assert_ne!(hash, "hunter2", "stored hash must not be the plaintext");
        assert!(
            hash.starts_with("$argon2id$"),
            "expected an Argon2id PHC string"
        );
        assert!(verify_password("hunter2", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn same_password_yields_different_hashes() {
        let a = hash_password("same-secret").unwrap();
        let b = hash_password("same-secret").unwrap();
        assert_ne!(a, b, "a fresh random salt must make the two hashes differ");
        // ...yet each still verifies against the original password.
        assert!(verify_password("same-secret", &a));
        assert!(verify_password("same-secret", &b));
    }

    #[test]
    fn tokens_are_high_entropy_hex_and_unique() {
        let token = new_token();
        assert_eq!(token.len(), 64, "32 bytes -> 64 hex chars (256 bits)");
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(new_token(), new_token(), "tokens must not repeat");
    }

    #[test]
    fn role_strings_round_trip() {
        for role in [Role::Admin, Role::User] {
            assert_eq!(Role::parse(role.as_str()).unwrap(), role);
        }
        assert!(matches!(Role::parse("root"), Err(Error::Database(_))));
    }

    #[test]
    fn lifetimes_clamp_without_overflow() {
        // A normal value converts directly.
        assert_eq!(clamp_lifetime(3600), Duration::seconds(3600));
        // An absurd value is capped instead of overflowing the conversion.
        assert_eq!(
            clamp_lifetime(u64::MAX),
            Duration::seconds(MAX_LIFETIME_SECS as i64)
        );
    }
}
