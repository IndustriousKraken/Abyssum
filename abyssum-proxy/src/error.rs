//! The proxy's error type — deliberately small; the proxy is a standalone surface
//! and does not share `abyssum-core`'s error model.

/// Anything that can go wrong starting or running the observing proxy.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Filesystem / socket I/O.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The traffic store (open / record / query).
    #[error("traffic store error: {0}")]
    Store(String),
    /// CA generation or TLS termination.
    #[error("tls error: {0}")]
    Tls(String),
    /// The outbound leg to the real destination, or the inbound connection.
    #[error("relay error: {0}")]
    Upstream(String),
    /// Invalid runtime configuration (e.g. exposing the read/replay API unsafely).
    #[error("configuration error: {0}")]
    Config(String),
}

/// The proxy's `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;
