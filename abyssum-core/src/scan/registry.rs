//! The scanner registry: stable id -> scanner factory.
//!
//! Scanners are addressed by their stable id. The registry maps each id to a
//! *factory* (`Fn(Arc<Config>) -> Box<dyn BaseScanner>`) so every scan session
//! gets a fresh scanner instance rather than sharing one across sessions.
//! [`available`](ScannerRegistry::available) lists the ids a scan may select, and
//! [`create`](ScannerRegistry::create) builds one — erroring with
//! [`Error::ScannerNotFound`] for an unknown id, *before* any traffic is issued.

use std::collections::HashMap;
use std::sync::Arc;

use crate::config::Config;
use crate::error::{Error, Result};

use super::scanner::BaseScanner;

/// Builds a fresh scanner instance from the shared config. Cloneable and
/// `Send + Sync` so the registry can be shared behind an `Arc`.
pub type ScannerFactory = Arc<dyn Fn(Arc<Config>) -> Box<dyn BaseScanner> + Send + Sync>;

/// Maps each stable scanner id to its factory.
pub struct ScannerRegistry {
    config: Arc<Config>,
    factories: HashMap<String, ScannerFactory>,
}

impl ScannerRegistry {
    /// An empty registry that will build scanners against `config`.
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            factories: HashMap::new(),
        }
    }

    /// Register `factory` under stable `id`. A later registration for the same id
    /// replaces the earlier one.
    pub fn register(&mut self, id: impl Into<String>, factory: ScannerFactory) {
        self.factories.insert(id.into(), factory);
    }

    /// The stable ids of every registered scanner, sorted for deterministic
    /// output (the backing map's order is unspecified).
    pub fn available(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.factories.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Whether `id` is registered. Used to validate a scan's selection up front.
    pub fn contains(&self, id: &str) -> bool {
        self.factories.contains_key(id)
    }

    /// Build a fresh scanner for `id`, or [`Error::ScannerNotFound`] if unknown.
    pub fn create(&self, id: &str) -> Result<Box<dyn BaseScanner>> {
        self.factories
            .get(id)
            .map(|factory| factory(self.config.clone()))
            .ok_or_else(|| Error::ScannerNotFound(id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{Finding, ScanContext, Target};
    use async_trait::async_trait;

    /// A minimal stub scanner identified by a fixed id.
    struct StubScanner {
        id: &'static str,
    }

    #[async_trait]
    impl BaseScanner for StubScanner {
        fn id(&self) -> &str {
            self.id
        }
        fn name(&self) -> &str {
            "Stub"
        }
        fn description(&self) -> &str {
            "Stub scanner"
        }
        async fn scan(&self, _t: &Target, _c: &ScanContext) -> Result<Vec<Finding>> {
            Ok(Vec::new())
        }
    }

    fn registry_with_two() -> ScannerRegistry {
        let mut reg = ScannerRegistry::new(Arc::new(Config::default()));
        reg.register(
            "alpha",
            Arc::new(|_cfg| Box::new(StubScanner { id: "alpha" }) as Box<dyn BaseScanner>),
        );
        reg.register(
            "beta",
            Arc::new(|_cfg| Box::new(StubScanner { id: "beta" }) as Box<dyn BaseScanner>),
        );
        reg
    }

    /// Task 4.4: available() lists both ids, create builds each, unknown errors.
    #[test]
    fn lists_creates_and_rejects_unknown() {
        let reg = registry_with_two();

        assert_eq!(
            reg.available(),
            vec!["alpha".to_string(), "beta".to_string()]
        );

        let a = reg.create("alpha").unwrap();
        assert_eq!(a.id(), "alpha");
        let b = reg.create("beta").unwrap();
        assert_eq!(b.id(), "beta");

        match reg.create("missing") {
            Err(Error::ScannerNotFound(id)) => assert_eq!(id, "missing"),
            Ok(_) => panic!("unknown id must not create a scanner"),
            Err(other) => panic!("expected ScannerNotFound, got {other:?}"),
        }
    }

    #[test]
    fn create_yields_fresh_instances() {
        let reg = registry_with_two();
        let first = reg.create("alpha").unwrap();
        let second = reg.create("alpha").unwrap();
        // Distinct boxes (different heap allocations) — fresh per call. Compare
        // the *data* addresses as thin pointers (a wide trait-object comparison
        // is ambiguous and lints).
        let p1 = first.as_ref() as *const dyn BaseScanner as *const ();
        let p2 = second.as_ref() as *const dyn BaseScanner as *const ();
        assert!(!std::ptr::eq(p1, p2));
    }

    #[test]
    fn contains_reflects_registration() {
        let reg = registry_with_two();
        assert!(reg.contains("alpha"));
        assert!(!reg.contains("nope"));
    }
}
