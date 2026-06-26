//! The scan session: the observable record of one run.
//!
//! A [`ScanSession`] holds what was requested (targets, selected scanner ids),
//! where it is in its lifecycle ([`SessionStatus`]), what it has produced
//! (aggregated findings, an error count), and its timing. The orchestrator owns
//! the state transitions; this module owns the shape and the derived
//! [`progress`](ScanSession::progress).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::finding::Finding;
use super::target::Target;

/// The observable lifecycle of a scan session.
///
/// `Pending -> Running -> {Completed | Cancelled | Errored}`. `Errored` is
/// reserved for a session-level failure (no scanner could run at all);
/// individual per-target scanner errors are *counted* but leave the session
/// `Completed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    /// Created and validated, not yet started.
    Pending,
    /// Actively running scanners over targets.
    Running,
    /// Finished; every selected unit was attempted.
    Completed,
    /// Stopped early by cancellation; partial findings retained.
    Cancelled,
    /// Could not run at all (e.g. no scanner could be constructed).
    Errored,
}

impl SessionStatus {
    /// Whether this is a terminal state (the scan has ended).
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            SessionStatus::Completed | SessionStatus::Cancelled | SessionStatus::Errored
        )
    }
}

/// Tested-units-out-of-total progress for a whole session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionProgress {
    /// Scanner-target units completed so far.
    pub completed: usize,
    /// Total scanner-target units to run (`scanners * targets`).
    pub total: usize,
}

impl SessionProgress {
    /// Completion as a fraction in `[0.0, 1.0]`; `1.0` when there is no work.
    pub fn fraction(&self) -> f64 {
        if self.total == 0 {
            1.0
        } else {
            (self.completed as f64 / self.total as f64).clamp(0.0, 1.0)
        }
    }
}

/// The full state of one scan run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSession {
    /// Stable session identifier.
    pub id: Uuid,
    /// Targets the session scans.
    pub targets: Vec<Target>,
    /// Stable ids of the selected scanners.
    pub scanner_ids: Vec<String>,
    /// Where the session is in its lifecycle.
    pub status: SessionStatus,
    /// Every finding aggregated from every scanner over every target.
    pub findings: Vec<Finding>,
    /// Count of per-target scanner errors encountered (does not abort the run).
    pub error_count: usize,
    /// Scanner-target units completed so far.
    pub completed_units: usize,
    /// Total scanner-target units (`scanner_ids.len() * targets.len()`).
    pub total_units: usize,
    /// When the run started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,
    /// When the run ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
    /// The id of the user that owns this session, stamped once at creation and
    /// never changed thereafter (see `add-authentication`, c02). `None` for
    /// CLI-initiated sessions, which have no owner; the web surface sets it to the
    /// authenticated creator. Visibility (owner-only + admin-sees-all) is enforced
    /// in [`auth`](crate::auth) against this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_user_id: Option<i64>,
}

impl ScanSession {
    /// A fresh `Pending` session with a new id. The orchestrator is the usual
    /// constructor (it validates ids first); this is the plain state container.
    pub fn new(targets: Vec<Target>, scanner_ids: Vec<String>) -> Self {
        let total_units = scanner_ids.len().saturating_mul(targets.len());
        Self {
            id: Uuid::new_v4(),
            targets,
            scanner_ids,
            status: SessionStatus::Pending,
            findings: Vec::new(),
            error_count: 0,
            completed_units: 0,
            total_units,
            started_at: None,
            finished_at: None,
            owner_user_id: None,
        }
    }

    /// Stamp the owning user's id (builder-style). The web surface calls this at
    /// creation with the authenticated user's id; CLI sessions leave it unset.
    /// Ownership is immutable once persisted — the store never overwrites it on a
    /// re-save.
    pub fn with_owner(mut self, owner_user_id: i64) -> Self {
        self.owner_user_id = Some(owner_user_id);
        self
    }

    /// Completion as tested-units / total-units.
    pub fn progress(&self) -> SessionProgress {
        SessionProgress {
            completed: self.completed_units,
            total: self.total_units,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(n: usize) -> Vec<Target> {
        (0..n)
            .map(|i| Target::parse(&format!("https://t{i}.example.com")).unwrap())
            .collect()
    }

    #[test]
    fn new_session_is_pending_with_total_units() {
        let s = ScanSession::new(targets(3), vec!["a".into(), "b".into()]);
        assert_eq!(s.status, SessionStatus::Pending);
        assert_eq!(s.total_units, 6); // 2 scanners * 3 targets
        assert_eq!(s.completed_units, 0);
        assert!(s.findings.is_empty());
        assert_eq!(s.error_count, 0);
        assert!(s.started_at.is_none());
    }

    #[test]
    fn progress_reports_completed_over_total() {
        let mut s = ScanSession::new(targets(2), vec!["a".into()]);
        assert_eq!(s.progress().fraction(), 0.0);
        s.completed_units = 1;
        assert_eq!(
            s.progress(),
            SessionProgress {
                completed: 1,
                total: 2
            }
        );
        assert_eq!(s.progress().fraction(), 0.5);
    }

    #[test]
    fn empty_work_progress_is_complete() {
        let s = ScanSession::new(vec![], vec![]);
        assert_eq!(s.total_units, 0);
        assert_eq!(s.progress().fraction(), 1.0);
    }

    #[test]
    fn terminal_states_are_flagged() {
        assert!(!SessionStatus::Pending.is_terminal());
        assert!(!SessionStatus::Running.is_terminal());
        assert!(SessionStatus::Completed.is_terminal());
        assert!(SessionStatus::Cancelled.is_terminal());
        assert!(SessionStatus::Errored.is_terminal());
    }

    #[test]
    fn status_serde_is_lowercase() {
        assert_eq!(
            serde_json::to_string(&SessionStatus::Running).unwrap(),
            "\"running\""
        );
    }
}
