//! Abyssum scanners.
//!
//! This crate holds the scanner implementations, each implementing the shared
//! [`BaseScanner`](abyssum_core::BaseScanner) contract from `abyssum-core`. A
//! scanner owns none of the cross-cutting concerns — pacing, the rotating
//! User-Agent, cancellation, and progress all arrive in the
//! [`ScanContext`](abyssum_core::ScanContext), and every request routes through
//! its paced `send`, so the stealth floor cannot be bypassed.
//!
//! [`rest_discovery`] is the first scanner and the template the rest follow;
//! [`openapi_discovery`] is the second (OpenAPI/Swagger spec exposure); [`cors`]
//! is the third (permissive cross-origin policy detection); [`bac`] is the fourth
//! (broken access control — sensitive paths reachable unauthenticated); [`idor`]
//! is the fifth (insecure direct object references — enumerable cross-object
//! access); [`graphql`] is the sixth (GraphQL endpoint detection plus
//! introspection / query-depth / batching / disclosure checks);
//! [`subdomain_recon`] is the seventh (passive subdomain discovery plus
//! subdomain-takeover detection); [`origin_discovery`] is the eighth (finding the
//! true origin IP of a CDN/WAF-fronted host from passive sources and confirming it).
//!
//! Register a scanner against a [`ScannerRegistry`](abyssum_core::ScannerRegistry)
//! with its module's `register` helper; [`register_builtins`] wires up every
//! scanner this crate ships.

pub mod bac;
pub mod cors;
pub mod graphql;
pub mod idor;
pub mod openapi_discovery;
pub mod origin_discovery;
pub mod rest_discovery;
pub mod subdomain_recon;

pub use bac::BacScanner;
pub use cors::CorsScanner;
pub use graphql::GraphqlScanner;
pub use idor::IdorScanner;
pub use openapi_discovery::OpenApiDiscoveryScanner;
pub use origin_discovery::OriginDiscoveryScanner;
pub use rest_discovery::RestDiscoveryScanner;
pub use subdomain_recon::SubdomainReconScanner;

use abyssum_core::{ReferenceStore, ScannerRegistry};

/// Register every built-in scanner against `registry`, baking in the seeded
/// reference-data `store` the wordlist-backed scanners read from. Surfaces call
/// this once at startup so every scanner becomes selectable by its stable id.
pub fn register_builtins(registry: &mut ScannerRegistry, store: &ReferenceStore) {
    rest_discovery::register(registry, store);
    openapi_discovery::register(registry, store);
    // The CORS scanner crafts its origins inline and reads no seeded store.
    cors::register(registry);
    bac::register(registry, store);
    // The IDOR scanner's reference/neighbour lists are inline heuristics, not a
    // seeded wordlist, so it reads no store either.
    idor::register(registry);
    // The GraphQL scanner loads its candidate paths and probe queries from the
    // seeded store (graphql_paths / graphql_queries).
    graphql::register(registry, store);
    // The subdomain-recon scanner's passive sources and takeover fingerprints are
    // inline, but its opt-in active brute-force joins the seeded `subdomains`
    // wordlist onto the apex, so it takes the store.
    subdomain_recon::register(registry, store);
    // The origin-discovery scanner's passive sources and CDN fingerprints are
    // inline, so it reads no seeded store.
    origin_discovery::register(registry);
}
