//! A rotating, realistic-by-default [`UserAgentSource`].
//!
//! This is the concrete source `add-seed-data` supplies for the engine's
//! [`UserAgentSource`] seam (defined by orchestration). Because
//! [`ScanContext::send`](crate::scan::ScanContext::send) stamps the source's value
//! on *every* outbound request — there is no unpaced request path — wiring this
//! source in means ordinary scan traffic blends in with realistic browser/mobile
//! identities rather than announcing a scanner to an IDS/IPS. That stealth posture
//! is half of Abyssum's identity (see `openspec/project.md`).
//!
//! Scanner-announcing identities (curl, python-requests, the Abyssum signature,
//! …) live in the pool too, but are reached only by *explicitly* selecting one
//! (e.g. via [`SingleUserAgent`](crate::scan::SingleUserAgent)); they are never in
//! the default rotation.

use std::sync::Mutex;

use rand::Rng;

use crate::config::UserAgentRotation;
use crate::error::Result;
use crate::scan::context::DEFAULT_USER_AGENT;
use crate::scan::UserAgentSource;

use super::store::ReferenceStore;

/// A [`UserAgentSource`] that draws from the realistic subset of the seeded pool,
/// varying the identity across requests.
///
/// Rotation granularity follows the `scanning.user_agent_rotation` config key:
///
/// - [`UserAgentRotation::PerRequest`] (the default) — each call picks a fresh
///   identity, and never repeats the immediately previous one, so rotation is
///   always observable on the wire.
/// - [`UserAgentRotation::PerScan`] — the first call pins one identity and every
///   later call returns it, so a single scan presents one stable browser
///   identity. Build a fresh source per scan to rotate *between* scans.
#[derive(Debug)]
pub struct RotatingUserAgent {
    /// The realistic identities to rotate through (never empty; see [`new`]).
    ///
    /// [`new`]: RotatingUserAgent::new
    pool: Vec<String>,
    /// Rotation granularity.
    mode: UserAgentRotation,
    /// Index of the last identity returned under per-request rotation, so the
    /// next pick can avoid an immediate repeat.
    last: Mutex<Option<usize>>,
    /// The identity pinned under per-scan rotation (chosen on first use).
    pinned: Mutex<Option<String>>,
}

impl RotatingUserAgent {
    /// Build a source over an explicit pool of (realistic) User-Agent values.
    ///
    /// An empty pool falls back to the bundled realistic identities, so the
    /// source is never degenerate even if the store has not been seeded.
    pub fn new(pool: Vec<String>, mode: UserAgentRotation) -> Self {
        let pool = if pool.is_empty() {
            fallback_pool()
        } else {
            pool
        };
        Self {
            pool,
            mode,
            last: Mutex::new(None),
            pinned: Mutex::new(None),
        }
    }

    /// Build a source from the realistic subset seeded in `store`, honoring the
    /// configured rotation granularity. Falls back to the bundled realistic
    /// identities if the store has not been seeded yet.
    pub async fn from_store(store: &ReferenceStore, mode: UserAgentRotation) -> Result<Self> {
        let pool = store.realistic_user_agents().await?;
        Ok(Self::new(pool, mode))
    }

    /// The realistic identities this source rotates through.
    pub fn pool(&self) -> &[String] {
        &self.pool
    }

    /// Pick an identity at random, avoiding an immediate repeat so consecutive
    /// requests differ whenever the pool holds more than one entry.
    fn pick(&self) -> String {
        match self.pool.len() {
            0 => DEFAULT_USER_AGENT.to_string(), // unreachable: `new` guarantees non-empty
            1 => self.pool[0].clone(),
            len => {
                // Recover from a poisoned lock rather than propagating the panic:
                // the guarded value is just a last-index hint, so a poisoned state
                // is harmless to reuse, and a single panic must not take every
                // later UA pick (and thus the whole scan) down with it.
                let mut last = self.last.lock().unwrap_or_else(|e| e.into_inner());
                let mut rng = rand::thread_rng();
                // Rejection-sample so every identity *other than* the immediately
                // previous one is equally likely. A deterministic `(idx + 1) % len`
                // shift on collision would bias index `(last + 1) % len` to roughly
                // twice the others; for a small realistic pool that skew is
                // measurable, so we draw again instead.
                let idx = loop {
                    let candidate = rng.gen_range(0..len);
                    if Some(candidate) != *last {
                        break candidate;
                    }
                };
                *last = Some(idx);
                self.pool[idx].clone()
            }
        }
    }
}

impl UserAgentSource for RotatingUserAgent {
    fn next_user_agent(&self) -> String {
        match self.mode {
            UserAgentRotation::PerRequest => self.pick(),
            UserAgentRotation::PerScan => {
                // Same resilience as `pick`: recover the pinned identity from a
                // poisoned lock instead of panicking every subsequent request.
                let mut pinned = self.pinned.lock().unwrap_or_else(|e| e.into_inner());
                pinned.get_or_insert_with(|| self.pick()).clone()
            }
        }
    }
}

/// The bundled realistic identities — a never-empty fallback for when the DB pool
/// is unavailable (e.g. an unseeded store).
fn fallback_pool() -> Vec<String> {
    super::assets::parse_user_agents()
        .into_iter()
        .filter(|ua| ua.realistic)
        .map(|ua| ua.value)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> Vec<String> {
        vec!["A".to_string(), "B".to_string(), "C".to_string()]
    }

    #[test]
    fn per_request_rotation_varies_and_never_immediately_repeats() {
        let src = RotatingUserAgent::new(pool(), UserAgentRotation::PerRequest);
        let mut seen = std::collections::BTreeSet::new();
        let mut prev: Option<String> = None;
        for _ in 0..200 {
            let ua = src.next_user_agent();
            assert!(pool().contains(&ua));
            assert_ne!(Some(&ua), prev.as_ref(), "immediate repeat under rotation");
            seen.insert(ua.clone());
            prev = Some(ua);
        }
        assert!(seen.len() > 1, "rotation never varied");
    }

    #[test]
    fn per_scan_rotation_pins_one_identity() {
        let src = RotatingUserAgent::new(pool(), UserAgentRotation::PerScan);
        let first = src.next_user_agent();
        for _ in 0..50 {
            assert_eq!(src.next_user_agent(), first);
        }
    }

    #[test]
    fn empty_pool_falls_back_to_bundled_realistic_identities() {
        let src = RotatingUserAgent::new(Vec::new(), UserAgentRotation::PerRequest);
        assert!(!src.pool().is_empty());
        // The fallback pool is realistic-only (no scanner signature).
        assert!(src.pool().iter().all(|ua| !ua.contains("Abyssum")));
    }

    #[test]
    fn single_entry_pool_returns_that_entry() {
        let src = RotatingUserAgent::new(vec!["only".to_string()], UserAgentRotation::PerRequest);
        assert_eq!(src.next_user_agent(), "only");
        assert_eq!(src.next_user_agent(), "only");
    }
}
