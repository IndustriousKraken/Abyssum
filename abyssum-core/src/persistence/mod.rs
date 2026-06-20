//! Durable result storage — the substrate every later surface reads and writes.
//!
//! A scan is worthless if its findings vanish when the process exits. This module
//! persists scan **sessions** and the **findings** they produce in an embedded
//! SQLite store so they survive a restart, and exposes querying and filtering over
//! that history. The single entry point is [`DatabaseManager`], which owns the
//! connection pool, applies migrations on startup, and serves every operation.
//!
//! The store is deliberately **ownership-blind**: it stores and queries scans and
//! findings without any notion of who owns them. The `authentication` change owns
//! user/ownership and extends the schema with an owner column via its own
//! migration; until then a surface scopes statistics by supplying the relevant
//! session ids (see [`DatabaseManager::summary_counts`]).
//!
//! The record shapes ([`SessionRecord`], [`StoredSession`], [`StoredFinding`], …)
//! are decoupled from the orchestrator's live `ScanSession` but reuse the shared
//! value vocabulary, so a stored record speaks the same shape every surface does.

mod db;
mod records;

pub use db::DatabaseManager;
pub use records::{
    FindingFilter, SessionRecord, SessionWithFindings, StoredFinding, StoredSession, SummaryCounts,
};
