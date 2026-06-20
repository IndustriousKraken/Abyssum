//! The rotating User-Agent source — the stealth default for outbound scans.
//!
//! This is the [`UserAgentSource`] implementation the `add-scan-orchestration`
//! seam was designed for. It draws from the realistic (browser/mobile) subset of
//! the seeded pool and varies the identity across calls, so every request issued
//! through `ScanContext::send` blends in with ordinary traffic rather than
//! announcing a scanner to an IDS/IPS (the project's Design Philosophy).
//!
//! Selection is a fresh uniform draw per call, matching the rate limiter's
//! anti-fingerprinting stance: a fixed round-robin would itself be a pattern. To
//! present a *specific* (or deliberately non-realistic) identity instead — an
//! explicit operator opt-in — use [`SingleUserAgent`](crate::scan::SingleUserAgent)
//! with the chosen value; [`RotatingUserAgent::pinned`] picks one realistic
//! identity and fixes it for a whole scan (the per-scan rotation granularity).

use std::sync::Arc;

use rand::Rng;

use crate::error::{Error, Result};
use crate::scan::{SingleUserAgent, UserAgentSource, DEFAULT_USER_AGENT};

use super::store::SeedStore;

/// A User-Agent source backed by a fixed pool, returning a uniformly random
/// member on each call. Built from the realistic subset of the seeded pool, it is
/// the default stealth rotation; the pool is a cheap shared snapshot so the source
/// is trivially cloneable across scan contexts.
#[derive(Debug, Clone)]
pub struct RotatingUserAgent {
    agents: Arc<Vec<String>>,
}

impl RotatingUserAgent {
    /// Build a rotating source over a non-empty pool of User-Agent strings.
    /// Returns [`Error::Seed`] for an empty pool — a source that could present no
    /// identity is a configuration error, not a silent fallback.
    pub fn new(agents: Vec<String>) -> Result<Self> {
        if agents.is_empty() {
            return Err(Error::Seed(
                "cannot build a rotating User-Agent source from an empty pool".to_string(),
            ));
        }
        Ok(Self {
            agents: Arc::new(agents),
        })
    }

    /// Build the default stealth source: the realistic subset of the seeded pool.
    /// Returns [`Error::Seed`] if the store holds no realistic entries (i.e. it was
    /// never seeded), so the caller can fall back deliberately rather than scan
    /// with no identity.
    pub async fn from_store(store: &SeedStore) -> Result<Self> {
        Self::new(store.realistic_user_agents().await?)
    }

    /// The pool this source rotates over.
    pub fn pool(&self) -> &[String] {
        &self.agents
    }

    /// Pick one identity now and fix it: a [`SingleUserAgent`] that presents the
    /// same realistic UA for every request. This is the per-scan rotation
    /// granularity — one identity held for a whole session — drawn from the same
    /// realistic pool as per-request rotation.
    pub fn pinned(&self) -> SingleUserAgent {
        SingleUserAgent::new(self.pick())
    }

    /// A fresh uniform draw from the pool. The pool is non-empty by construction;
    /// the guard only protects a hand-rolled empty `agents` from panicking.
    fn pick(&self) -> String {
        if self.agents.is_empty() {
            return DEFAULT_USER_AGENT.to_string();
        }
        let index = rand::thread_rng().gen_range(0..self.agents.len());
        self.agents[index].clone()
    }
}

impl UserAgentSource for RotatingUserAgent {
    fn next_user_agent(&self) -> String {
        self.pick()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn pool() -> Vec<String> {
        vec![
            "Mozilla/5.0 A".to_string(),
            "Mozilla/5.0 B".to_string(),
            "Mozilla/5.0 C".to_string(),
        ]
    }

    #[test]
    fn empty_pool_is_rejected() {
        let err = RotatingUserAgent::new(Vec::new()).unwrap_err();
        assert!(matches!(err, Error::Seed(_)), "got {err:?}");
    }

    #[test]
    fn every_draw_is_from_the_pool() {
        let agents = pool();
        let src = RotatingUserAgent::new(agents.clone()).unwrap();
        for _ in 0..200 {
            assert!(agents.contains(&src.next_user_agent()));
        }
    }

    #[test]
    fn draws_vary_across_many_calls() {
        let src = RotatingUserAgent::new(pool()).unwrap();
        let seen: HashSet<String> = (0..200).map(|_| src.next_user_agent()).collect();
        assert!(seen.len() > 1, "rotation must not be constant");
    }

    #[test]
    fn pinned_is_constant_and_from_the_pool() {
        let agents = pool();
        let pinned = RotatingUserAgent::new(agents.clone()).unwrap().pinned();
        let first = pinned.next_user_agent();
        assert!(agents.contains(&first));
        for _ in 0..50 {
            assert_eq!(
                pinned.next_user_agent(),
                first,
                "a pinned UA must not change"
            );
        }
    }
}
