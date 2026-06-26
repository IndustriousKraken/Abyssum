//! Scan orchestration — the engine every scanner and surface shares.
//!
//! This module defines the orchestration vocabulary the rest of the build
//! depends on, in four cooperating pieces:
//!
//! - **Shared value types** — [`Target`], [`Severity`], [`Status`], [`Finding`]:
//!   the cross-cutting shapes every scanner, persistence, and surface speak.
//! - **[`BaseScanner`]** — the contract a scanner implements: stable identity
//!   plus a single `scan(target, ctx)` operation.
//! - **[`ScanContext`]** — what a scanner is handed at run time. Its
//!   [`send`](ScanContext::send) is the *only* path to the network, so every
//!   request is paced through the shared rate limiter and carries an
//!   engine-applied User-Agent — the pacing floor cannot be bypassed.
//! - **[`ScannerRegistry`]** and **[`Orchestrator`]** — selection by stable id,
//!   and the session lifecycle (running → completed / cancelled / errored) with
//!   finding aggregation, progress, and cancellation.
//!
//! Defining these here — the change where the scanner trait is born — is what
//! keeps the six scanners from each inventing their own vocabulary.

pub mod context;
pub mod finding;
pub mod orchestrator;
pub mod progress;
pub mod registry;
pub mod scanner;
pub mod session;
pub mod target;

pub use context::{
    Credential, Method, RequestSpec, ScanContext, SingleUserAgent, UserAgentSource,
    DEFAULT_USER_AGENT,
};
pub use finding::{Finding, FindingBuilder, FindingId, Severity, Status};
pub use orchestrator::{Orchestrator, SessionHandle};
pub use progress::{ProgressCallback, ProgressKind, ProgressUpdate};
pub use registry::{ScannerFactory, ScannerRegistry};
pub use scanner::BaseScanner;
pub use session::{ScanSession, SessionProgress, SessionStatus};
pub use target::Target;
