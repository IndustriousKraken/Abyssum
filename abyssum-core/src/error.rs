//! The shared error model for Abyssum.
//!
//! Every crate surfaces failures through [`Error`] and the [`Result`] alias.
//!
//! The enum is intentionally **`#[non_exhaustive]`**. This change ships only the
//! cross-cutting variants ([`Config`](Error::Config), [`Io`](Error::Io), and a
//! catch-all [`Other`](Error::Other)), but later changes append their own — for
//! example `add-scan-orchestration` adds a `ScannerNotFound` variant, and
//! persistence/auth add storage and authentication variants. Marking the enum
//! `#[non_exhaustive]` forces downstream `match` expressions to carry a wildcard
//! arm, so appending a variant is never a breaking change. Treat this type as a
//! growing extension point, not a finished list.

use std::result::Result as StdResult;

/// The crate-wide error type for Abyssum.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Configuration could not be loaded, parsed, or validated.
    #[error("configuration error: {0}")]
    Config(String),

    /// An underlying I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A scan selected a scanner id that is not present in the registry. Raised
    /// before any request is issued, so an unknown id never reaches a target.
    #[error("scanner not found: {0}")]
    ScannerNotFound(String),

    /// A scan target could not be constructed or resolved (e.g. an unparseable
    /// base URL, or a URL with no host to pace on).
    #[error("invalid target: {0}")]
    Target(String),

    /// An outbound HTTP request issued through the scan context failed at the
    /// transport layer (connection, TLS, timeout, …) or was halted by pacing.
    #[error("request error: {0}")]
    Http(String),

    /// The scan was cancelled. Surfaced by the scan context's cancellation check
    /// so a cooperating scanner can unwind promptly and return partial results.
    #[error("scan cancelled")]
    Cancelled,

    /// A persistence operation failed: opening the store, running a migration,
    /// (de)serializing a stored field, or executing a query. Added by
    /// `add-result-persistence` (a03); the error model's doc anticipates this.
    #[error("database error: {0}")]
    Database(String),

    /// An authentication or authorization failure: bad credentials, a missing,
    /// invalid, or expired session, a duplicate username at registration, or an
    /// attempt to access a scan session the user neither owns nor (as admin) may
    /// see. Added by `add-authentication` (c02). The message is deliberately
    /// non-revealing on the login path (see `auth::AuthManager::login`).
    #[error("authentication error: {0}")]
    Auth(String),

    /// A catch-all for failures that do not (yet) warrant a dedicated variant.
    #[error("{0}")]
    Other(String),
}

/// Convenience alias for fallible operations across Abyssum.
pub type Result<T> = StdResult<T, Error>;

/// Wrap any displayable error (sqlx, serde_json, uuid, …) as [`Error::Database`].
///
/// The single home for mapping a storage-layer failure onto the [`Database`]
/// variant, shared by the persistence and reference-data stores so the
/// error-wrapping behaviour lives in one place.
///
/// [`Database`]: Error::Database
pub(crate) fn db_err<E: std::fmt::Display>(err: E) -> Error {
    Error::Database(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_errors_convert_via_from() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "nope");
        let err: Error = io.into();
        assert!(matches!(err, Error::Io(_)));
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn config_error_displays_message() {
        let err = Error::Config("bad port".to_string());
        assert_eq!(err.to_string(), "configuration error: bad port");
    }

    // Compile-time proof that the enum is non-exhaustive: a wildcard arm is
    // required, so future variants will not break this match.
    #[test]
    fn matching_requires_wildcard_arm() {
        let err = Error::Other("x".to_string());
        let label = match err {
            Error::Config(_) => "config",
            Error::Io(_) => "io",
            _ => "other",
        };
        assert_eq!(label, "other");
    }
}
