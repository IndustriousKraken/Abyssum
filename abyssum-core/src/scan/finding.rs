//! The canonical finding record and its severity/status vocabularies.
//!
//! Every scanner result is one [`Finding`]. Keeping a single type — with a single
//! [`Severity`] scale and a single [`Status`] disposition — is what stops the six
//! scanners from each inventing their own shape: the registry, persistence,
//! reporting, and both surfaces all speak this exact record.
//!
//! `Finding` is this build's name for the v1 `ScanResult`. Severity is
//! **required** (defaulting to [`Severity::Info`], never omitted); the stable
//! [`id`](Finding::id) is `None` until persistence assigns one on save.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::target::Target;

/// The fixed, ordered severity scale shared by all scanners.
///
/// Ordering is by declaration: `Info` is the floor and `Critical` the ceiling,
/// so severities are directly comparable and filterable across scanners. A
/// scanner that reports only an observation uses `Info` rather than omitting a
/// severity.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational — a neutral observation, not a weakness. The floor.
    #[default]
    Info,
    /// Low impact.
    Low,
    /// Medium impact.
    Medium,
    /// High impact.
    High,
    /// Critical impact. The ceiling.
    Critical,
}

/// The fixed disposition shared by all scanners: a confirmed weakness, a
/// checked-and-sound result, or a neutral observation.
///
/// Scanner-specific labels ("accessible", "introspection enabled") belong in the
/// finding's title or description — never as new status values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// A confirmed weakness worth reporting.
    Vulnerable,
    /// Checked and found sound.
    Safe,
    /// A neutral observation.
    #[default]
    Info,
}

impl Status {
    /// Whether a finding with this status is one a consumer would report (i.e.
    /// it is [`Status::Vulnerable`]).
    pub fn is_reportable(self) -> bool {
        matches!(self, Status::Vulnerable)
    }
}

/// The stable identifier persistence assigns to a saved finding.
pub type FindingId = i64;

/// One scanner result, described identically for every scanner.
///
/// Build with [`Finding::builder`]. Required up front: the producing
/// `scanner_id`, the `target`, and a human-readable `title`. `severity` defaults
/// to [`Severity::Info`] and `status` to [`Status::Info`]; `timestamp` defaults
/// to now. The [`id`](Finding::id) stays `None` until persistence saves it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable identifier, assigned by persistence on save (`None` until then).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<FindingId>,
    /// The stable id of the scanner that produced this finding.
    pub scanner_id: String,
    /// The target this finding concerns.
    pub target: Target,
    /// Severity — required, drawn from the shared scale.
    pub severity: Severity,
    /// Status — required, drawn from the shared disposition set.
    pub status: Status,
    /// Human-readable one-line summary.
    pub title: String,
    /// Optional longer description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional structured evidence (request/response excerpts, headers, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<serde_json::Value>,
    /// Optional remediation guidance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendations: Option<String>,
    /// When the finding was produced.
    pub timestamp: DateTime<Utc>,
}

impl Finding {
    /// Start building a finding from its required fields.
    pub fn builder(
        scanner_id: impl Into<String>,
        target: Target,
        title: impl Into<String>,
    ) -> FindingBuilder {
        FindingBuilder {
            scanner_id: scanner_id.into(),
            target,
            severity: Severity::default(),
            status: Status::default(),
            title: title.into(),
            description: None,
            evidence: None,
            recommendations: None,
            timestamp: None,
        }
    }
}

/// Builder for [`Finding`]. Required fields are supplied to
/// [`Finding::builder`]; everything else has a default, so [`build`](Self::build)
/// is infallible.
#[derive(Debug, Clone)]
pub struct FindingBuilder {
    scanner_id: String,
    target: Target,
    severity: Severity,
    status: Status,
    title: String,
    description: Option<String>,
    evidence: Option<serde_json::Value>,
    recommendations: Option<String>,
    timestamp: Option<DateTime<Utc>>,
}

impl FindingBuilder {
    /// Set the severity (defaults to [`Severity::Info`]).
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Set the status (defaults to [`Status::Info`]).
    pub fn status(mut self, status: Status) -> Self {
        self.status = status;
        self
    }

    /// Set the optional longer description.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the optional structured evidence.
    pub fn evidence(mut self, evidence: serde_json::Value) -> Self {
        self.evidence = Some(evidence);
        self
    }

    /// Set the optional remediation guidance.
    pub fn recommendations(mut self, recommendations: impl Into<String>) -> Self {
        self.recommendations = Some(recommendations.into());
        self
    }

    /// Override the timestamp (defaults to [`Utc::now`] at build time).
    pub fn timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    /// Finish building. The stable `id` is left `None` for persistence to assign.
    pub fn build(self) -> Finding {
        Finding {
            id: None,
            scanner_id: self.scanner_id,
            target: self.target,
            severity: self.severity,
            status: self.status,
            title: self.title,
            description: self.description,
            evidence: self.evidence,
            recommendations: self.recommendations,
            timestamp: self.timestamp.unwrap_or_else(Utc::now),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::parse("https://example.com").unwrap()
    }

    #[test]
    fn severity_orders_info_lowest_critical_highest() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
        let mut levels = [
            Severity::Critical,
            Severity::Info,
            Severity::High,
            Severity::Low,
            Severity::Medium,
        ];
        levels.sort();
        assert_eq!(
            levels,
            [
                Severity::Info,
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical
            ]
        );
    }

    #[test]
    fn severity_default_is_info_floor() {
        assert_eq!(Severity::default(), Severity::Info);
    }

    #[test]
    fn status_default_is_info_and_only_vulnerable_is_reportable() {
        assert_eq!(Status::default(), Status::Info);
        assert!(Status::Vulnerable.is_reportable());
        assert!(!Status::Safe.is_reportable());
        assert!(!Status::Info.is_reportable());
    }

    #[test]
    fn severity_serde_uses_lowercase_names() {
        assert_eq!(serde_json::to_string(&Severity::High).unwrap(), "\"high\"");
        let s: Severity = serde_json::from_str("\"critical\"").unwrap();
        assert_eq!(s, Severity::Critical);
    }

    #[test]
    fn status_serde_uses_lowercase_names() {
        assert_eq!(
            serde_json::to_string(&Status::Vulnerable).unwrap(),
            "\"vulnerable\""
        );
        let s: Status = serde_json::from_str("\"safe\"").unwrap();
        assert_eq!(s, Status::Safe);
    }

    #[test]
    fn builder_defaults_severity_status_and_id() {
        let f = Finding::builder("rest_discovery", target(), "Endpoint reachable").build();
        assert_eq!(f.scanner_id, "rest_discovery");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.status, Status::Info);
        assert_eq!(f.title, "Endpoint reachable");
        assert!(
            f.id.is_none(),
            "id is assigned by persistence, not the builder"
        );
        assert!(f.description.is_none());
        assert!(f.evidence.is_none());
    }

    #[test]
    fn builder_sets_optional_fields() {
        let f = Finding::builder("cors", target(), "Permissive CORS")
            .severity(Severity::High)
            .status(Status::Vulnerable)
            .description("Reflects arbitrary Origin")
            .evidence(serde_json::json!({ "origin": "https://evil.test" }))
            .recommendations("Restrict allowed origins")
            .build();
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.status, Status::Vulnerable);
        assert_eq!(f.description.as_deref(), Some("Reflects arbitrary Origin"));
        assert_eq!(f.evidence.unwrap()["origin"], "https://evil.test");
        assert_eq!(
            f.recommendations.as_deref(),
            Some("Restrict allowed origins")
        );
    }

    #[test]
    fn finding_serde_round_trips() {
        let f = Finding::builder("idor", target(), "Reference enumerable")
            .severity(Severity::Critical)
            .status(Status::Vulnerable)
            .build();
        let json = serde_json::to_string(&f).unwrap();
        let back: Finding = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }
}
