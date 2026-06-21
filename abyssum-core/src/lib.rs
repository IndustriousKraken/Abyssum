//! Abyssum core library.
//!
//! This crate owns the cross-cutting foundations every Abyssum surface (CLI and
//! web) shares: layered [`config`]uration loading, the shared [`error`] model,
//! and structured [`logging`]. Keeping these here — and keeping the binaries
//! thin — means the two surfaces call one engine and cannot drift.
//!
//! Later changes extend this crate with scan orchestration, rate limiting,
//! persistence, and auth; the [`Error`] enum is deliberately open for those to
//! append to (see [`error`]).

pub mod config;
pub mod error;
pub mod logging;

pub use config::Config;
pub use error::{Error, Result};
