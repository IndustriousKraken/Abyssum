//! Progress reporting during a scan.
//!
//! Two granularities flow through the same [`ProgressUpdate`] shape: a scanner's
//! own internal progress ("tested 12 / 100, current `/admin`"), delivered via the
//! [`ProgressCallback`] carried in the scan context, and the orchestrator's
//! unit-level progress ("completed 3 / 6 scanner-target units"). A surface
//! subscribes to the orchestrator's [broadcast stream](crate::scan::Orchestrator)
//! to render either live.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// A single progress report.
///
/// `items_completed` out of `total_items` says how far along the unit of work is;
/// `current_item` names what is being tested right now.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProgressUpdate {
    /// The id of the scanner this update concerns (or the orchestrator's view of
    /// the active scanner for unit-level updates).
    pub scanner_id: String,
    /// How many units have been tested so far.
    pub items_completed: usize,
    /// The total number of units to test.
    pub total_items: usize,
    /// What is currently being tested (e.g. a path or a target URL), if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_item: Option<String>,
    /// A free-form human-readable message.
    #[serde(default)]
    pub message: String,
}

impl ProgressUpdate {
    /// Build a progress update.
    pub fn new(scanner_id: impl Into<String>, items_completed: usize, total_items: usize) -> Self {
        Self {
            scanner_id: scanner_id.into(),
            items_completed,
            total_items,
            current_item: None,
            message: String::new(),
        }
    }

    /// Set the item currently being tested (builder-style).
    pub fn current_item(mut self, item: impl Into<String>) -> Self {
        self.current_item = Some(item.into());
        self
    }

    /// Set the human-readable message (builder-style).
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    /// Completion as a fraction in `[0.0, 1.0]`; `1.0` when there is no work.
    pub fn fraction(&self) -> f64 {
        if self.total_items == 0 {
            1.0
        } else {
            (self.items_completed as f64 / self.total_items as f64).clamp(0.0, 1.0)
        }
    }
}

/// The callback a scan context invokes to report progress. Cheaply cloneable and
/// `Send + Sync` so it can be shared across tasks and fanned out to a broadcast.
pub type ProgressCallback = Arc<dyn Fn(ProgressUpdate) + Send + Sync>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn fraction_reports_completion_ratio() {
        let u = ProgressUpdate::new("s", 3, 6);
        assert_eq!(u.fraction(), 0.5);
        assert_eq!(ProgressUpdate::new("s", 0, 0).fraction(), 1.0);
        assert_eq!(ProgressUpdate::new("s", 10, 4).fraction(), 1.0);
    }

    #[test]
    fn builder_sets_current_and_message() {
        let u = ProgressUpdate::new("rest", 1, 4)
            .current_item("/admin")
            .message("probing");
        assert_eq!(u.current_item.as_deref(), Some("/admin"));
        assert_eq!(u.message, "probing");
    }

    #[test]
    fn callback_receives_updates() {
        let seen: Arc<Mutex<Vec<ProgressUpdate>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        let cb: ProgressCallback = Arc::new(move |u| sink.lock().unwrap().push(u));
        cb(ProgressUpdate::new("s", 1, 2));
        cb(ProgressUpdate::new("s", 2, 2));
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[test]
    fn serde_round_trips() {
        let u = ProgressUpdate::new("s", 2, 5)
            .current_item("/x")
            .message("m");
        let json = serde_json::to_string(&u).unwrap();
        let back: ProgressUpdate = serde_json::from_str(&json).unwrap();
        assert_eq!(u, back);
    }
}
