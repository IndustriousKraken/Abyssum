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
pub(crate) mod csv;
pub mod custom_request;
pub mod diff;
pub mod error;
pub mod logging;
pub mod persistence;
pub mod rate_limiter;
pub mod report;
pub mod scan;
pub mod seed;
pub mod timing;
pub mod wordlists;

pub use ai::analyze_finding;
pub use annotations::{AnnotationStore, DEFAULT_TAG_COLOR, Note, Tag, TagApply, TagUsage};
pub use auth::{AuthManager, Role, User, visible_session, visible_sessions};
pub use config::{
    AiConfig, AuthConfig, Config, UserAgentRotation, default_config_path, default_database_path,
};
pub use custom_request::{
    CaptureResult, CapturedResponse, CustomRequestSpec, DEFAULT_BODY_PREVIEW_CAP,
    DEFAULT_MAX_BODY_BYTES, DEFAULT_TIMEOUT, OutputFormat, PreparedRequest, RequestOutcome, Signal,
    SignalKind, analyze, execute as execute_custom_request, normalize_url,
};
pub use diff::{ChangedEntry, DiffEntry, SessionDiff, diff_sessions};
pub use error::{Error, Result};
pub use persistence::{
    DEFAULT_SEARCH_LIMIT, DatabaseManager, FindingFilter, MAX_SEARCH_LIMIT, Summary,
};
pub use rate_limiter::{Pace, PacingPolicy, RateLimiter};
pub use report::{ReportFormat, ReportGenerator, ReportOptions};
pub use scan::{
    BaseScanner, Credential, Finding, FindingBuilder, FindingId, Identity, Method, Orchestrator,
    ProgressCallback, ProgressKind, ProgressUpdate, RequestSpec, ScanContext, ScanOptions,
    ScanSession, ScannerFactory, ScannerRegistry, SessionHandle, SessionProgress, SessionStatus,
    Severity, SingleUserAgent, Status, Target, UserAgentSource, run_differential,
};
pub use seed::{PooledUserAgent, ReferenceStore, RotatingUserAgent, SeedUserAgent, WordlistEntry};
pub use timing::{
    DEFAULT_PROFILE_NAME, TIMING_POLICY_OPTION, TimingProfile, TimingProfileStore, builtin_library,
};
pub use tokio_util::sync::CancellationToken;
pub use wordlists::{CustomWordlist, CustomWordlistStore, ImportReport};
