//! Curated reference data: bundled wordlists and the User-Agent pool.
//!
//! Abyssum's scanners depend on curated reference data — per-scanner
//! path/query wordlists and a pool of realistic User-Agent strings — that is part
//! of the product's value. Rather than hard-coding it as throwaway constants, this
//! capability ships it as assets embedded in the binary ([`assets`]) and seeds it
//! into the database on first run, where it is queryable and extensible at runtime
//! ([`store`]). The same store backs the engine's rotating, realistic-by-default
//! User-Agent source ([`user_agent`]).
//!
//! The three pieces:
//!
//! - [`assets`] — the embedded files and their parsing into entries.
//! - [`store::ReferenceStore`] — idempotent seeding plus named lookups; the single
//!   source scanners read their candidates from.
//! - [`user_agent::RotatingUserAgent`] — the stealth User-Agent source wired into
//!   the engine's [`UserAgentSource`](crate::scan::UserAgentSource) seam.

pub mod assets;
pub mod store;
pub mod user_agent;

pub use assets::{
    parse_user_agents, parse_wordlist, ParsedEntry, SeedUserAgent, WordlistAsset, WORDLISTS,
};
pub use store::{PooledUserAgent, ReferenceStore, WordlistEntry};
pub use user_agent::RotatingUserAgent;
