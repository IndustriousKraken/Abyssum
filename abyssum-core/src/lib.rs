//! Abyssum core library.
//!
//! This crate owns the cross-cutting foundations every Abyssum surface (CLI and
//! web) shares: layered [`config`]uration loading, the shared [`error`] model,
//! and structured [`logging`]. Keeping these here — and keeping the binaries
//! thin — means the two surfaces call one engine and cannot drift.
//!
//! It also owns the shared pacing authority — the [`rate_limiter`] — so that every
//! scanner routes its outbound timing through one place and the stealth floor is
//! structurally enforceable.
//!
//! Later changes extend this crate with persistence and auth; the [`Error`] enum
//! is deliberately open for those to append to (see [`error`]). The [`scan`]
//! orchestration engine (added in `add-scan-orchestration`, a02) holds one
//! cheaply-cloneable [`RateLimiter`] and shares it with every scanner through the
//! [`ScanContext`](scan::ScanContext), so the pacing floor cannot be bypassed.

pub mod config;
pub mod error;
pub mod logging;
pub mod rate_limiter;
pub mod scan;

pub use config::Config;
pub use error::{Error, Result};
pub use rate_limiter::{Pace, RateLimiter};
pub use scan::{
    BaseScanner, Credential, Finding, FindingBuilder, FindingId, Method, Orchestrator,
    ProgressCallback, ProgressUpdate, RequestSpec, ScanContext, ScanSession, ScannerFactory,
    ScannerRegistry, SessionHandle, SessionProgress, SessionStatus, Severity, SingleUserAgent,
    Status, Target, UserAgentSource,
};
