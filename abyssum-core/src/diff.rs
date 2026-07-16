//! Diffing two stored scan sessions.
//!
//! For repeat and unattended scanning the useful output is not the full finding
//! list each time but *what changed since last run*. [`diff_sessions`] compares an
//! older (baseline) and a newer session and reports, for the same targets:
//! findings present in the newer run only (**added**), present in the older run
//! only (**resolved**), and findings matched across both whose severity or status
//! changed (**changed**). Findings identical in both are counted but excluded from
//! the detail.
//!
//! Findings are matched by [`Finding::consolidation_key`] — the producing scanner,
//! the normalized endpoint, and the title — the same key a report uses to collapse
//! duplicates, so "the same issue" means the same thing across both features. Like
//! that consolidation, when a session carries several findings under one key the
//! first-seen one stands in for the group.
//!
//! A diff is a pure function of stored data: no network I/O, no re-scan, so it is
//! deterministic and testable from in-memory sessions.

use std::collections::BTreeMap;

use serde::Serialize;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::scan::{Finding, ScanSession, Severity, Status};

/// The matching key: scanner id + normalized endpoint + title.
type Key = (String, String, String);

/// One finding on one side of a diff (an added or resolved entry).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DiffEntry {
    /// The producing scanner's id.
    pub scanner: String,
    /// The normalized target endpoint (canonical URL).
    pub target: String,
    /// The finding's title (its class).
    pub title: String,
    /// The finding's severity.
    pub severity: Severity,
    /// The finding's status.
    pub status: Status,
}

impl DiffEntry {
    fn from_finding(finding: &Finding) -> Self {
        Self {
            scanner: finding.scanner_id.clone(),
            target: finding.target.full_url().to_string(),
            title: finding.title.clone(),
            severity: finding.severity,
            status: finding.status,
        }
    }
}

/// A finding matched across both sessions whose severity or status changed.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChangedEntry {
    /// The producing scanner's id.
    pub scanner: String,
    /// The normalized target endpoint (canonical URL).
    pub target: String,
    /// The finding's title (its class).
    pub title: String,
    /// Severity in the older session.
    pub old_severity: Severity,
    /// Severity in the newer session.
    pub new_severity: Severity,
    /// Status in the older session.
    pub old_status: Status,
    /// Status in the newer session.
    pub new_status: Status,
}

/// The difference between two scan sessions' findings.
///
/// `added`, `resolved`, and `changed` are each ordered deterministically by their
/// matching key, so the same pair of sessions always yields the same diff.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SessionDiff {
    /// The older (baseline) session's id.
    pub older_session: Uuid,
    /// The newer session's id.
    pub newer_session: Uuid,
    /// Findings present in the newer session but not the older.
    pub added: Vec<DiffEntry>,
    /// Findings present in the older session but not the newer.
    pub resolved: Vec<DiffEntry>,
    /// Findings matched across both whose severity or status differs.
    pub changed: Vec<ChangedEntry>,
    /// How many matched findings were identical in both (excluded from the detail).
    pub unchanged: usize,
}

impl SessionDiff {
    /// Whether the diff has no detailed entries (nothing added, resolved, or
    /// changed). Unchanged findings do not count.
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.resolved.is_empty() && self.changed.is_empty()
    }

    /// Render the diff as an aligned, human-readable table: one row per added,
    /// changed, or resolved finding, with a trailing summary of the unchanged count.
    pub fn render_table(&self) -> String {
        const COLUMNS: [&str; 6] = ["Change", "Scanner", "Target", "Title", "From", "To"];
        let mut rows: Vec<[String; 6]> = Vec::new();
        for e in &self.added {
            rows.push(row("added", e, "—", &state(e.severity, e.status)));
        }
        for c in &self.changed {
            rows.push([
                "changed".into(),
                c.scanner.clone(),
                c.target.clone(),
                c.title.clone(),
                state(c.old_severity, c.old_status),
                state(c.new_severity, c.new_status),
            ]);
        }
        for e in &self.resolved {
            rows.push(row("resolved", e, &state(e.severity, e.status), "—"));
        }

        let collapsed: Vec<[String; 6]> = rows
            .iter()
            .map(|r| std::array::from_fn(|i| collapse_whitespace(&r[i])))
            .collect();
        let mut widths: [usize; 6] = COLUMNS.map(str::len);
        for r in &collapsed {
            for (i, cell) in r.iter().enumerate() {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }

        let mut out = String::new();
        push_row(&mut out, &COLUMNS.map(String::from), &widths);
        let separators: [String; 6] = std::array::from_fn(|i| "-".repeat(widths[i]));
        push_row(&mut out, &separators, &widths);
        for r in &collapsed {
            push_row(&mut out, r, &widths);
        }
        if collapsed.is_empty() {
            out.push_str("(no changes)\n");
        }
        out.push_str(&format!(
            "\n{} unchanged finding(s) not shown.\n",
            self.unchanged
        ));
        out
    }

    /// Render the diff as pretty-printed, machine-readable JSON.
    pub fn render_json(&self) -> Result<String> {
        let mut json = serde_json::to_string_pretty(self)
            .map_err(|e| Error::Other(format!("failed to render the diff as JSON: {e}")))?;
        json.push('\n');
        Ok(json)
    }

    /// Render the diff as CSV: a stable header row plus one row per added, changed,
    /// or resolved finding (unchanged findings are summarized only, so they carry no
    /// row).
    pub fn render_csv(&self) -> String {
        let mut out = String::from("change,scanner,target,title,from,to\n");
        for e in &self.added {
            csv_row(
                &mut out,
                "added",
                &e.scanner,
                &e.target,
                &e.title,
                "",
                &state(e.severity, e.status),
            );
        }
        for c in &self.changed {
            csv_row(
                &mut out,
                "changed",
                &c.scanner,
                &c.target,
                &c.title,
                &state(c.old_severity, c.old_status),
                &state(c.new_severity, c.new_status),
            );
        }
        for e in &self.resolved {
            csv_row(
                &mut out,
                "resolved",
                &e.scanner,
                &e.target,
                &e.title,
                &state(e.severity, e.status),
                "",
            );
        }
        out
    }
}

/// Diff two sessions: `older` is the baseline, `newer` the follow-up.
///
/// Findings are matched by [`Finding::consolidation_key`]; the first finding seen
/// under a key in each session stands in for that key. A matched pair is *changed*
/// when its severity or status differs and *unchanged* otherwise.
pub fn diff_sessions(older: &ScanSession, newer: &ScanSession) -> SessionDiff {
    let old_index = index(older);
    let new_index = index(newer);

    let mut added = Vec::new();
    let mut changed = Vec::new();
    let mut unchanged = 0;
    // BTreeMap iterates in key order, so the outputs are deterministic.
    for (key, new_f) in &new_index {
        match old_index.get(key) {
            None => added.push(DiffEntry::from_finding(new_f)),
            Some(old_f) => {
                if old_f.severity != new_f.severity || old_f.status != new_f.status {
                    changed.push(ChangedEntry {
                        scanner: new_f.scanner_id.clone(),
                        target: new_f.target.full_url().to_string(),
                        title: new_f.title.clone(),
                        old_severity: old_f.severity,
                        new_severity: new_f.severity,
                        old_status: old_f.status,
                        new_status: new_f.status,
                    });
                } else {
                    unchanged += 1;
                }
            }
        }
    }

    let resolved = old_index
        .iter()
        .filter(|(key, _)| !new_index.contains_key(*key))
        .map(|(_, old_f)| DiffEntry::from_finding(old_f))
        .collect();

    SessionDiff {
        older_session: older.id,
        newer_session: newer.id,
        added,
        resolved,
        changed,
        unchanged,
    }
}

/// Index a session's findings by their matching key, keeping the first finding
/// seen under each key (matching a report's first-seen consolidation).
fn index(session: &ScanSession) -> BTreeMap<Key, &Finding> {
    let mut map: BTreeMap<Key, &Finding> = BTreeMap::new();
    for finding in &session.findings {
        map.entry(finding.consolidation_key()).or_insert(finding);
    }
    map
}

/// The `severity/status` descriptor shown for one side of an entry.
fn state(severity: Severity, status: Status) -> String {
    format!("{}/{}", severity_wire(severity), status_wire(status))
}

/// A table row for an added/resolved entry, given its `from`/`to` state cells.
fn row(change: &str, e: &DiffEntry, from: &str, to: &str) -> [String; 6] {
    [
        change.into(),
        e.scanner.clone(),
        e.target.clone(),
        e.title.clone(),
        from.into(),
        to.into(),
    ]
}

/// Append one `" | "`-separated, right-padded table row.
fn push_row(out: &mut String, row: &[String; 6], widths: &[usize; 6]) {
    let padded: Vec<String> = row
        .iter()
        .enumerate()
        .map(|(i, cell)| {
            let pad = widths[i].saturating_sub(cell.chars().count());
            format!("{cell}{}", " ".repeat(pad))
        })
        .collect();
    out.push_str(padded.join(" | ").trim_end());
    out.push('\n');
}

/// Append one escaped CSV record.
fn csv_row(
    out: &mut String,
    change: &str,
    scanner: &str,
    target: &str,
    title: &str,
    from: &str,
    to: &str,
) {
    let fields = [change, scanner, target, title, from, to];
    let escaped: Vec<String> = fields.iter().map(|f| crate::csv::escape(f)).collect();
    out.push_str(&escaped.join(","));
    out.push('\n');
}

/// Collapse any run of whitespace (including newlines) into single spaces so a
/// multi-line title cannot break the table layout.
fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The lowercase wire spelling of a severity (matches its serde name).
fn severity_wire(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// The lowercase wire spelling of a status (matches its serde name).
fn status_wire(status: Status) -> &'static str {
    match status {
        Status::Vulnerable => "vulnerable",
        Status::Safe => "safe",
        Status::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::Target;

    fn target(url: &str) -> Target {
        Target::parse(url).unwrap()
    }

    fn f(scanner: &str, url: &str, title: &str, sev: Severity, status: Status) -> Finding {
        Finding::builder(scanner, target(url), title)
            .severity(sev)
            .status(status)
            .build()
    }

    fn session(findings: Vec<Finding>) -> ScanSession {
        let mut s = ScanSession::new(vec![target("https://api.example.com")], vec!["cors".into()]);
        s.findings = findings;
        s
    }

    /// The core scenario (task 7.5): one added, one resolved, one changed, and an
    /// unchanged finding excluded from the detail.
    #[test]
    fn reports_added_resolved_and_changed_exactly() {
        let older = session(vec![
            // Stays identical → unchanged (counted, not listed).
            f(
                "cors",
                "https://api.example.com/a",
                "Same",
                Severity::Low,
                Status::Info,
            ),
            // Present only in older → resolved.
            f(
                "bac",
                "https://api.example.com/admin",
                "Admin open",
                Severity::High,
                Status::Vulnerable,
            ),
            // Severity/status change between runs → changed.
            f(
                "idor",
                "https://api.example.com/users/1",
                "Enumerable",
                Severity::Low,
                Status::Safe,
            ),
        ]);
        let newer = session(vec![
            f(
                "cors",
                "https://api.example.com/a",
                "Same",
                Severity::Low,
                Status::Info,
            ),
            // Present only in newer → added.
            f(
                "rest_discovery",
                "https://api.example.com/debug",
                "Debug route",
                Severity::Medium,
                Status::Vulnerable,
            ),
            f(
                "idor",
                "https://api.example.com/users/1",
                "Enumerable",
                Severity::High,
                Status::Vulnerable,
            ),
        ]);

        let diff = diff_sessions(&older, &newer);

        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].title, "Debug route");
        assert_eq!(diff.resolved.len(), 1);
        assert_eq!(diff.resolved[0].title, "Admin open");
        assert_eq!(diff.changed.len(), 1);
        let ch = &diff.changed[0];
        assert_eq!(ch.title, "Enumerable");
        assert_eq!(ch.old_severity, Severity::Low);
        assert_eq!(ch.new_severity, Severity::High);
        assert_eq!(ch.old_status, Status::Safe);
        assert_eq!(ch.new_status, Status::Vulnerable);
        assert_eq!(diff.unchanged, 1);
        assert!(!diff.is_empty());
    }

    /// Identical sessions produce an empty delta (task 7.5) — only the unchanged
    /// count is non-zero.
    #[test]
    fn identical_sessions_have_empty_delta() {
        let findings = || {
            vec![
                f(
                    "cors",
                    "https://api.example.com/a",
                    "One",
                    Severity::High,
                    Status::Vulnerable,
                ),
                f(
                    "idor",
                    "https://api.example.com/b",
                    "Two",
                    Severity::Low,
                    Status::Info,
                ),
            ]
        };
        let diff = diff_sessions(&session(findings()), &session(findings()));
        assert!(diff.added.is_empty());
        assert!(diff.resolved.is_empty());
        assert!(diff.changed.is_empty());
        assert_eq!(diff.unchanged, 2);
        assert!(diff.is_empty());
    }

    /// The renderers agree on the same categories: the table names each change kind
    /// and the transition, JSON round-trips the entries, CSV carries one row each.
    #[test]
    fn renderers_reflect_the_categories() {
        let older = session(vec![f(
            "bac",
            "https://api.example.com/x",
            "Gone",
            Severity::High,
            Status::Vulnerable,
        )]);
        let newer = session(vec![f(
            "cors",
            "https://api.example.com/y",
            "New",
            Severity::Medium,
            Status::Vulnerable,
        )]);
        let diff = diff_sessions(&older, &newer);

        let table = diff.render_table();
        assert!(table.contains("added"));
        assert!(table.contains("resolved"));
        assert!(table.contains("New"));
        assert!(table.contains("medium/vulnerable"));
        assert!(table.contains("0 unchanged finding(s)"));

        let json = diff.render_json().unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["added"].as_array().unwrap().len(), 1);
        assert_eq!(value["resolved"].as_array().unwrap().len(), 1);
        assert_eq!(value["added"][0]["severity"], "medium");
        assert_eq!(value["added"][0]["status"], "vulnerable");
        assert_eq!(value["unchanged"], 0);

        let csv = diff.render_csv();
        let mut lines = csv.lines();
        assert_eq!(lines.next().unwrap(), "change,scanner,target,title,from,to");
        assert_eq!(csv.lines().count(), 3, "header + one added + one resolved");
    }

    /// Duplicate keys within a session collapse to the first-seen finding, matching
    /// a report's consolidation, so they don't inflate the diff.
    #[test]
    fn duplicate_keys_collapse_to_first_seen() {
        let older = session(vec![]);
        let newer = session(vec![
            f(
                "cors",
                "https://api.example.com/a",
                "Dup",
                Severity::High,
                Status::Vulnerable,
            ),
            f(
                "cors",
                "https://api.example.com/a",
                "Dup",
                Severity::Low,
                Status::Info,
            ),
        ]);
        let diff = diff_sessions(&older, &newer);
        assert_eq!(diff.added.len(), 1, "one key, one added entry");
        assert_eq!(diff.added[0].severity, Severity::High, "first-seen wins");
    }
}
