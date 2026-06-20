//! Abyssum scanners.
//!
//! This crate holds the scanner implementations, each implementing the shared
//! [`BaseScanner`](abyssum_core::BaseScanner) contract from `abyssum-core`. The
//! first scanner — [`RestDiscoveryScanner`] — is the foundational reconnaissance
//! check and the template the remaining five (OpenAPI/Swagger exposure, CORS, BAC,
//! IDOR, GraphQL) follow as later changes land.
//!
//! Scanners own none of the cross-cutting concerns: pacing, the rotating
//! User-Agent, progress, cancellation, and the HTTP client all arrive in the
//! [`ScanContext`](abyssum_core::ScanContext). The one thing a scanner needs that
//! the context does not carry is its curated wordlist, which reaches it through
//! the [`WordlistProvider`] seam at registration time.
//!
//! Surfaces wire the scanners into a [`ScannerRegistry`](abyssum_core::ScannerRegistry)
//! with [`register_default_scanners`], passing the seeded
//! [`SeedStore`](abyssum_core::SeedStore) as the wordlist source.

mod rest_discovery;
mod wordlist;

pub use rest_discovery::RestDiscoveryScanner;
pub use wordlist::{StaticWordlistProvider, WordlistProvider};

use std::sync::Arc;

use abyssum_core::{BaseScanner, ScannerRegistry};

/// Register the REST discovery scanner under its stable id, drawing candidates
/// from `wordlists`. Each scan session gets a fresh scanner instance sharing the
/// same wordlist source.
pub fn register_rest_discovery(
    registry: &mut ScannerRegistry,
    wordlists: Arc<dyn WordlistProvider>,
) {
    registry.register(
        RestDiscoveryScanner::ID,
        Arc::new(move |_config| {
            Box::new(RestDiscoveryScanner::new(wordlists.clone())) as Box<dyn BaseScanner>
        }),
    );
}

/// Register every scanner this crate provides into `registry`, all drawing their
/// curated wordlists from `wordlists` (in production, the seeded
/// [`SeedStore`](abyssum_core::SeedStore)). This is the one call a surface makes to
/// populate the registry.
pub fn register_default_scanners(
    registry: &mut ScannerRegistry,
    wordlists: Arc<dyn WordlistProvider>,
) {
    register_rest_discovery(registry, wordlists);
}

#[cfg(test)]
mod tests {
    use super::*;
    use abyssum_core::Config;

    /// Task 1.3: after registration the scanner is selectable by its stable id and
    /// builds with the right identity.
    #[test]
    fn registers_rest_discovery_by_stable_id() {
        let mut registry = ScannerRegistry::new(Arc::new(Config::default()));
        let provider = Arc::new(StaticWordlistProvider::new());
        register_default_scanners(&mut registry, provider);

        assert!(registry.contains("rest_discovery"));
        assert_eq!(registry.available(), vec!["rest_discovery".to_string()]);

        let scanner = registry.create("rest_discovery").unwrap();
        assert_eq!(scanner.id(), "rest_discovery");
        assert_eq!(scanner.name(), RestDiscoveryScanner::NAME);
        assert!(!scanner.description().is_empty());
    }
}
