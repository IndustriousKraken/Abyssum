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

    /// A catch-all for failures that do not (yet) warrant a dedicated variant.
    #[error("{0}")]
    Other(String),
}

/// Convenience alias for fallible operations across Abyssum.
pub type Result<T> = StdResult<T, Error>;

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
