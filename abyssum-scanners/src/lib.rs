//! Abyssum scanners.
//!
//! This crate holds the scanner implementations, each implementing the shared
//! [`BaseScanner`](abyssum_core::BaseScanner) contract from `abyssum-core`. A
//! scanner owns none of the cross-cutting concerns — pacing, the rotating
//! User-Agent, cancellation, and progress all arrive in the
//! [`ScanContext`](abyssum_core::ScanContext), and every request routes through
//! its paced `send`, so the stealth floor cannot be bypassed.
//!
//! [`rest_discovery`] is the first scanner and the template the rest follow
//! (OpenAPI/Swagger exposure, CORS, BAC, IDOR, GraphQL — added in later changes).
//!
//! Register a scanner against a [`ScannerRegistry`](abyssum_core::ScannerRegistry)
//! with its module's `register` helper; [`register_builtins`] wires up every
//! scanner this crate ships.

pub mod rest_discovery;

pub use rest_discovery::RestDiscoveryScanner;

use abyssum_core::{ReferenceStore, ScannerRegistry};

/// Register every built-in scanner against `registry`, baking in the seeded
/// reference-data `store` the scanners read their wordlists from. Surfaces call
/// this once at startup so every scanner becomes selectable by its stable id.
pub fn register_builtins(registry: &mut ScannerRegistry, store: &ReferenceStore) {
    rest_discovery::register(registry, store);
}
