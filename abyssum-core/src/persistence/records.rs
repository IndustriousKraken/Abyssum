//! The record shapes persistence stores and returns, plus the storage encoding
//! of the shared enums.
//!
//! These types are deliberately decoupled from the orchestrator's live
//! [`ScanSession`](crate::scan::ScanSession): persistence keeps what was produced
//! (identity, status, targets, scanner ids, timing, request/error counts and the
//! canonical findings) without the orchestrator's in-flight bookkeeping. They
//! reuse the *shared* value vocabulary — [`SessionStatus`], [`Status`],
//! [`Severity`], [`Target`], [`Finding`] — so a stored record speaks the same
//! shape every surface does.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::scan::{Finding, SessionStatus, Severity, Status, Target};

/// The writable fields of a scan session as persistence stores them.
///
/// This is the input to [`upsert_session`](super::DatabaseManager::upsert_session):
/// the durable identity and state of a run, minus the orchestrator's transient
/// progress counters. `total_requests` and `error_count` are the request/error
/// tallies for the run; the DB owns the `created_at`/`updated_at` bookkeeping
/// (surfaced on read via [`StoredSession`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// Stable public session identifier.
    pub session_id: Uuid,
    /// Where the session ended up (or currently is) in its lifecycle.
    pub status: SessionStatus,
    /// Targets the session covered.
    pub targets: Vec<Target>,
    /// Stable ids of the selected scanners.
    pub scanner_ids: Vec<String>,
    /// When the run started, if it had.
    pub start_time: Option<DateTime<Utc>>,
    /// When the run ended, if it had.
    pub end_time: Option<DateTime<Utc>>,
    /// Total outbound requests the run issued.
    pub total_requests: i64,
    /// Count of per-target scanner errors the run encountered.
    pub error_count: i64,
}

/// A session as read back from the store: its [`SessionRecord`] plus the DB's
/// creation/update bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSession {
    /// The durable session fields.
    pub record: SessionRecord,
    /// When the row was first written.
    pub created_at: DateTime<Utc>,
    /// When the row was last upserted.
    pub updated_at: DateTime<Utc>,
}

/// A finding as stored: the public stable `finding_id` persistence assigned, plus
/// the canonical [`Finding`] it was saved from (whose internal `id` carries the
/// row id once persisted).
#[derive(Debug, Clone, PartialEq)]
pub struct StoredFinding {
    /// Stable public identifier, unique across the store; downstream changes
    /// (annotations, reports) address a finding by this.
    pub finding_id: Uuid,
    /// The canonical finding record.
    pub finding: Finding,
}

/// A session together with its stored findings — the shape a surface uses to
/// render one run in full.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionWithFindings {
    /// The session.
    pub session: StoredSession,
    /// Every finding stored under it, oldest-first.
    pub findings: Vec<StoredFinding>,
}

/// A composable filter over stored findings.
///
/// Every field is optional; a `None` field is simply not constrained. Supplied
/// filters combine with AND, so adding a filter only ever narrows the result.
/// Build with [`FindingFilter::new`] and the chainable setters, or with a struct
/// literal (it derives [`Default`]).
#[derive(Debug, Clone, Default)]
pub struct FindingFilter {
    /// Restrict to one session.
    pub session_id: Option<Uuid>,
    /// Restrict to one status classification.
    pub status: Option<Status>,
    /// Restrict to one severity level.
    pub severity: Option<Severity>,
    /// Restrict to one producing scanner id.
    pub scanner_id: Option<String>,
    /// Restrict to one target (matched against the finding's full request URL).
    pub target: Option<String>,
    /// Free-text query matched (case-insensitively) against title and description.
    pub query: Option<String>,
    /// Inclusive lower bound on the finding timestamp.
    pub from: Option<DateTime<Utc>>,
    /// Inclusive upper bound on the finding timestamp.
    pub to: Option<DateTime<Utc>>,
    /// Maximum number of rows to return (defaults applied by the store).
    pub limit: Option<i64>,
}

impl FindingFilter {
    /// An empty filter — matches every finding.
    pub fn new() -> Self {
        Self::default()
    }

    /// Restrict to one session.
    pub fn session(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Restrict to one status.
    pub fn status(mut self, status: Status) -> Self {
        self.status = Some(status);
        self
    }

    /// Restrict to one severity.
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Restrict to one producing scanner id.
    pub fn scanner_id(mut self, scanner_id: impl Into<String>) -> Self {
        self.scanner_id = Some(scanner_id.into());
        self
    }

    /// Restrict to one target (full request URL).
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Match a free-text query over title and description.
    pub fn query(mut self, query: impl Into<String>) -> Self {
        self.query = Some(query.into());
        self
    }

    /// Constrain to findings recorded at or after `from` and at or before `to`.
    pub fn date_range(mut self, from: DateTime<Utc>, to: DateTime<Utc>) -> Self {
        self.from = Some(from);
        self.to = Some(to);
        self
    }

    /// Cap the number of returned rows.
    pub fn limit(mut self, limit: i64) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Aggregate counts over stored data, optionally restricted to a subset of
/// sessions. `by_severity` always carries an entry for every [`Severity`] level
/// (zero when none match), so a surface can render a full breakdown directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryCounts {
    /// Number of sessions counted.
    pub sessions: i64,
    /// Number of findings counted.
    pub findings: i64,
    /// Findings per severity level.
    pub by_severity: BTreeMap<Severity, i64>,
}

impl SummaryCounts {
    /// A zeroed summary with every severity present at 0.
    pub(crate) fn zeroed() -> Self {
        Self {
            sessions: 0,
            findings: 0,
            by_severity: severity_counts_zeroed(),
        }
    }
}

/// A `by_severity` map with every level present at zero, ready to be filled.
pub(crate) fn severity_counts_zeroed() -> BTreeMap<Severity, i64> {
    let mut map = BTreeMap::new();
    for severity in [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ] {
        map.insert(severity, 0);
    }
    map
}

// --- Storage encoding of the shared enums -------------------------------------
//
// Stored as their lowercase names (matching the JSON serde representation) so the
// scalar columns stay human-readable and directly filterable. Kept here, local to
// persistence, rather than on the enums themselves — this is a storage concern.

/// The stored token for a [`SessionStatus`].
pub(crate) fn session_status_to_str(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::Pending => "pending",
        SessionStatus::Running => "running",
        SessionStatus::Completed => "completed",
        SessionStatus::Cancelled => "cancelled",
        SessionStatus::Errored => "errored",
    }
}

/// Parse a stored [`SessionStatus`] token.
pub(crate) fn session_status_from_str(value: &str) -> Result<SessionStatus> {
    Ok(match value {
        "pending" => SessionStatus::Pending,
        "running" => SessionStatus::Running,
        "completed" => SessionStatus::Completed,
        "cancelled" => SessionStatus::Cancelled,
        "errored" => SessionStatus::Errored,
        other => {
            return Err(Error::Persistence(format!(
                "unknown session status in store: {other:?}"
            )))
        }
    })
}

/// The stored token for a [`Status`].
pub(crate) fn status_to_str(status: Status) -> &'static str {
    match status {
        Status::Vulnerable => "vulnerable",
        Status::Safe => "safe",
        Status::Info => "info",
    }
}

/// Parse a stored [`Status`] token.
pub(crate) fn status_from_str(value: &str) -> Result<Status> {
    Ok(match value {
        "vulnerable" => Status::Vulnerable,
        "safe" => Status::Safe,
        "info" => Status::Info,
        other => {
            return Err(Error::Persistence(format!(
                "unknown finding status in store: {other:?}"
            )))
        }
    })
}

/// The stored token for a [`Severity`].
pub(crate) fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Parse a stored [`Severity`] token.
pub(crate) fn severity_from_str(value: &str) -> Result<Severity> {
    Ok(match value {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        other => {
            return Err(Error::Persistence(format!(
                "unknown severity in store: {other:?}"
            )))
        }
    })
}
