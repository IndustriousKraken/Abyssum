//! The base scanner contract every scanner implements.
//!
//! A scanner exposes a stable identity (a stable [`id`](BaseScanner::id), a human
//! [`name`](BaseScanner::name), a [`description`](BaseScanner::description)) and a
//! single [`scan`](BaseScanner::scan) operation over one target. It owns none of
//! the cross-cutting concerns — pacing, progress, cancellation, and the HTTP
//! client all arrive in the [`ScanContext`]. The trait is object-safe (via
//! `async_trait`) so scanners live in the registry as `Box<dyn BaseScanner>`.

use async_trait::async_trait;

use crate::error::{Error, Result};

use super::context::ScanContext;
use super::finding::Finding;
use super::target::Target;

/// What every scanner implements.
#[async_trait]
pub trait BaseScanner: Send + Sync {
    /// The stable scanner id (e.g. `"rest_discovery"`). This is the value the
    /// registry keys on and a scan selects by — it must not change.
    fn id(&self) -> &str;

    /// A human-readable name for surfaces to display.
    fn name(&self) -> &str;

    /// A human-readable description of what the scanner checks.
    fn description(&self) -> &str;

    /// Scan a single `target`, returning zero or more findings. Pacing, progress,
    /// cancellation, and HTTP all come from `ctx`; the scanner must route every
    /// request through [`ScanContext::send`].
    async fn scan(&self, target: &Target, ctx: &ScanContext) -> Result<Vec<Finding>>;

    /// Validate that the scanner can handle `target` before it is run. The
    /// default accepts any target whose base URL names a host (so per-domain
    /// pacing has a key); scanners may override for stricter checks.
    fn validate_target(&self, target: &Target) -> Result<()> {
        if target.host().is_none() {
            return Err(Error::Target(format!(
                "target base URL has no host to scan: {}",
                target.base_url()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopScanner;

    #[async_trait]
    impl BaseScanner for NoopScanner {
        fn id(&self) -> &str {
            "noop"
        }
        fn name(&self) -> &str {
            "No-op scanner"
        }
        fn description(&self) -> &str {
            "Returns no findings"
        }
        async fn scan(&self, _target: &Target, _ctx: &ScanContext) -> Result<Vec<Finding>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn trait_is_object_safe() {
        let scanner: Box<dyn BaseScanner> = Box::new(NoopScanner);
        assert_eq!(scanner.id(), "noop");
        assert_eq!(scanner.name(), "No-op scanner");
        assert_eq!(scanner.description(), "Returns no findings");
    }

    #[test]
    fn default_validate_target_accepts_host_rejects_hostless() {
        let scanner = NoopScanner;
        let ok = Target::parse("https://example.com").unwrap();
        assert!(scanner.validate_target(&ok).is_ok());

        let hostless = Target::new(url::Url::parse("file:///tmp/x").unwrap(), None, None);
        assert!(matches!(
            scanner.validate_target(&hostless),
            Err(Error::Target(_))
        ));
    }
}
