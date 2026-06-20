//! The wordlist source a scanner draws its candidate paths from.
//!
//! A scanner is built by the registry's factory, which only carries the shared
//! [`Config`](abyssum_core::Config) — it has no handle to the database. So the
//! curated wordlists (seeded by `add-seed-data`) reach a scanner through this
//! small [`WordlistProvider`] seam, supplied when the scanner is registered.
//!
//! The production provider is the [`SeedStore`]: a named lookup against the
//! reference-data tables. Tests use [`StaticWordlistProvider`], an in-memory map,
//! so the probing/classification logic can be exercised without a database. An
//! absent list yields no candidates rather than failing — the same single-source
//! contract the store itself honours.

use std::collections::HashMap;

use async_trait::async_trait;

use abyssum_core::{Result, SeedStore};

/// Supplies a named wordlist's values, in seeded order.
///
/// This is the one dependency the scanner has on reference data; everything else
/// (pacing, HTTP, progress, cancellation) arrives in the
/// [`ScanContext`](abyssum_core::ScanContext). Keeping it a trait lets the scanner
/// be unit-tested against an in-memory list and run in production against the
/// seeded database, without the scanner changing shape.
#[async_trait]
pub trait WordlistProvider: Send + Sync {
    /// The values of the named wordlist, in order. An unknown name returns an
    /// empty vector (no candidates), never an error.
    async fn wordlist(&self, name: &str) -> Result<Vec<String>>;
}

/// The production provider: the seeded reference-data store. Looks each named list
/// up against the curated tables (`add-seed-data`).
#[async_trait]
impl WordlistProvider for SeedStore {
    async fn wordlist(&self, name: &str) -> Result<Vec<String>> {
        self.wordlist_values(name).await
    }
}

/// An in-memory provider for tests: a map of list name to values. A list that was
/// not configured returns no candidates, mirroring the store's contract.
#[derive(Debug, Default, Clone)]
pub struct StaticWordlistProvider {
    lists: HashMap<String, Vec<String>>,
}

impl StaticWordlistProvider {
    /// An empty provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add (or replace) a named list (builder-style).
    pub fn with_list(mut self, name: impl Into<String>, values: Vec<String>) -> Self {
        self.lists.insert(name.into(), values);
        self
    }
}

#[async_trait]
impl WordlistProvider for StaticWordlistProvider {
    async fn wordlist(&self, name: &str) -> Result<Vec<String>> {
        Ok(self.lists.get(name).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_provider_returns_configured_list() {
        let provider = StaticWordlistProvider::new()
            .with_list("rest_endpoints", vec!["health".into(), "users".into()]);
        assert_eq!(
            provider.wordlist("rest_endpoints").await.unwrap(),
            vec!["health".to_string(), "users".to_string()]
        );
    }

    #[tokio::test]
    async fn static_provider_unknown_list_is_empty_not_an_error() {
        let provider = StaticWordlistProvider::new();
        assert!(provider.wordlist("missing").await.unwrap().is_empty());
    }
}
