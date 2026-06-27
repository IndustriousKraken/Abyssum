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

pub mod ai;
pub mod annotations;
pub mod auth;
pub mod config;
pub mod custom_request;
pub mod error;
pub mod logging;
pub mod persistence;
pub mod rate_limiter;
pub mod report;
pub mod scan;
pub mod seed;

pub use ai::analyze_finding;
pub use annotations::{AnnotationStore, Note, Tag, TagApply, TagUsage, DEFAULT_TAG_COLOR};
pub use auth::{visible_session, visible_sessions, AuthManager, Role, User};
pub use config::{AiConfig, AuthConfig, Config, UserAgentRotation};
pub use custom_request::{
    analyze, execute as execute_custom_request, normalize_url, CaptureResult, CapturedResponse,
    CustomRequestSpec, OutputFormat, PreparedRequest, RequestOutcome, Signal, SignalKind,
    DEFAULT_BODY_PREVIEW_CAP, DEFAULT_MAX_BODY_BYTES, DEFAULT_TIMEOUT,
};
pub use error::{Error, Result};
pub use persistence::{
    DatabaseManager, FindingFilter, Summary, DEFAULT_SEARCH_LIMIT, MAX_SEARCH_LIMIT,
};
pub use rate_limiter::{Pace, RateLimiter};
pub use report::{ReportFormat, ReportGenerator, ReportOptions};
pub use scan::{
    BaseScanner, Credential, Finding, FindingBuilder, FindingId, Method, Orchestrator,
    ProgressCallback, ProgressKind, ProgressUpdate, RequestSpec, ScanContext, ScanSession,
    ScannerFactory, ScannerRegistry, SessionHandle, SessionProgress, SessionStatus, Severity,
    SingleUserAgent, Status, Target, UserAgentSource,
};
pub use seed::{PooledUserAgent, ReferenceStore, RotatingUserAgent, SeedUserAgent, WordlistEntry};
