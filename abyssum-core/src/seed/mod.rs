//! Curated reference data: the seed-data capability (a04).
//!
//! Abyssum's scanners depend on curated wordlists and a pool of realistic
//! User-Agent strings. That data is part of the product's value, so it must not be
//! throwaway constants: it lives in the database — queryable, inspectable, and
//! extensible at runtime — while still shipping inside the single self-contained
//! binary. The curated files under `assets/seed/` are embedded at build time (see
//! [`assets`]) and copied into the store on first run (see [`SeedStore`]).
//!
//! The capability has three faces:
//!
//! - **Storage & seeding** — [`SeedStore`] owns the reference-data tables (added
//!   by this crate's `0002_seed_data` migration) and seeds them idempotently from
//!   the embedded assets, topping up only missing rows.
//! - **Named lookup** — [`SeedStore::wordlist`] is the single source a scanner
//!   draws its candidate paths/queries from; an absent list returns no candidates
//!   rather than failing.
//! - **Stealth rotation** — [`RotatingUserAgent`] implements the engine's
//!   `UserAgentSource` seam from the realistic subset of the pool, so every
//!   outbound request blends in with ordinary traffic by default.

pub mod assets;
mod store;
mod user_agent;

pub use assets::{bundled_user_agents, bundled_wordlist, SeedUserAgent, WordlistEntry};
pub use store::{SeedStore, SeedSummary, UserAgentRecord};
pub use user_agent::RotatingUserAgent;

use crate::error::Result;
use crate::persistence::DatabaseManager;

/// Ensure the reference-data store is seeded, returning a [`SeedStore`] over the
/// database's pool. This is the one-call convenience for startup and installers:
/// it self-seeds the store (idempotently topping up missing rows) and hands back
/// the store ready for lookups. Equivalent to
/// [`SeedStore::from_manager`] followed by [`SeedStore::seed`].
pub async fn ensure_seeded(db: &DatabaseManager) -> Result<SeedStore> {
    let store = SeedStore::from_manager(db);
    store.seed().await?;
    Ok(store)
}
