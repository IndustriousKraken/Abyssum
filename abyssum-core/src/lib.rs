//! Abyssum core library.
//!
//! This crate owns the cross-cutting foundations every Abyssum surface (CLI and
//! web) shares: layered [`config`]uration loading, the shared [`error`] model,
//! and structured [`logging`]. Keeping these here — and keeping the binaries
//! thin — means the two surfaces call one engine and cannot drift.
//!
//! Later changes extend this crate with persistence and auth; the [`Error`] enum
//! is deliberately open for those to append to (see [`error`]). The
//! [`rate_limit`]er — Abyssum's single pacing authority — lives here too, and the
//! [`scan`] orchestration engine (this change) holds one and shares it with every
//! scanner through the [`ScanContext`](scan::ScanContext).

pub mod config;
pub mod error;
pub mod logging;
pub mod persistence;
pub mod rate_limit;
pub mod scan;

pub use config::Config;
pub use error::{Error, Result};
pub use persistence::{
    DatabaseManager, FindingFilter, SessionRecord, SessionWithFindings, StoredFinding,
    StoredSession, SummaryCounts,
};
pub use rate_limit::{Pace, RateLimiter};
pub use scan::{
    BaseScanner, Credential, Finding, FindingBuilder, FindingId, Method, Orchestrator,
    ProgressCallback, ProgressUpdate, RequestSpec, ScanContext, ScanSession, ScannerFactory,
    ScannerRegistry, SessionHandle, SessionProgress, SessionStatus, Severity, SingleUserAgent,
    Status, Target, UserAgentSource,
};
