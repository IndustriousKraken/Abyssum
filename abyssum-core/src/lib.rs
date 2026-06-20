//! Abyssum core library.
//!
//! This crate owns the cross-cutting foundations every Abyssum surface (CLI and
//! web) shares: layered [`config`]uration loading, the shared [`error`] model,
//! and structured [`logging`]. Keeping these here — and keeping the binaries
//! thin — means the two surfaces call one engine and cannot drift.
//!
//! Later changes extend this crate with scan orchestration, persistence, and
//! auth; the [`Error`] enum is deliberately open for those to append to (see
//! [`error`]). The [`rate_limit`]er — Abyssum's single pacing authority — lives
//! here too, ready for the scan context (built in `add-scan-orchestration`) to
//! hold and share with every scanner.

pub mod config;
pub mod error;
pub mod logging;
pub mod rate_limit;

pub use config::Config;
pub use error::{Error, Result};
pub use rate_limit::{Pace, RateLimiter};
