//! Reporting an external source that could not be consulted.
//!
//! Surface-mapping scanners lean on third-party sources (certificate transparency,
//! DoH resolvers, registration-data APIs). When one is down or answers with a
//! non-success status the scanner would otherwise return an empty result that is
//! indistinguishable from "nothing to find" — the worst failure mode for a recon
//! tool. [`SourceIssue`] records that a source could not be consulted, and
//! [`to_findings`] turns the collected issues into informational findings so the
//! gap is visible in the UI/CLI/reports, not only in the log.

use std::collections::HashSet;

use abyssum_core::{Finding, Severity, Status, Target};

/// A record that an external source a scanner relies on could not be consulted
/// successfully — it errored (no HTTP status) or returned a non-success status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceIssue {
    /// Human-readable source name, e.g. `"certificate transparency (crt.sh)"`.
    source: &'static str,
    /// The HTTP status the source returned, when it responded with one; `None` on a
    /// transport error / unreachable source.
    status: Option<u16>,
}

impl SourceIssue {
    /// Record a source that errored with no HTTP status (unreachable, transport
    /// failure).
    pub(crate) fn errored(source: &'static str) -> Self {
        Self {
            source,
            status: None,
        }
    }

    /// Record a source that responded with a non-success HTTP status.
    pub(crate) fn non_success(source: &'static str, status: u16) -> Self {
        Self {
            source,
            status: Some(status),
        }
    }

    /// Build the informational finding for this unavailable source, naming it (and
    /// the status, when there was one) and stating results may be incomplete.
    fn finding(&self, scanner_id: &str, target: &Target) -> Finding {
        let detail = match self.status {
            Some(status) => format!("returned a non-success status ({status})"),
            None => "could not be reached".to_string(),
        };
        Finding::builder(
            scanner_id,
            target.clone(),
            format!("Discovery source unavailable: {}", self.source),
        )
        .status(Status::Info)
        .severity(Severity::Info)
        .description(format!(
            "The external discovery source \"{}\" {detail}, so this scan's results may be \
             incomplete: an empty or partial result reflects a source that could not be \
             consulted, not necessarily an absence of findings. Re-run once the source is \
             reachable.",
            self.source,
        ))
        .evidence(serde_json::json!({
            "source": self.source,
            "status": self.status,
            "results_may_be_incomplete": true,
        }))
        .build()
    }
}

/// Turn collected source issues into findings, one per distinct source: a source
/// probed many times (e.g. a DoH resolver hit once per candidate) that fails
/// repeatedly yields a single finding, not one per call. First occurrence per
/// source wins, so the reported status is the first one observed.
pub(crate) fn to_findings(
    issues: Vec<SourceIssue>,
    scanner_id: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut seen = HashSet::new();
    issues
        .into_iter()
        .filter(|issue| seen.insert(issue.source))
        .map(|issue| issue.finding(scanner_id, target))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::parse("https://example.com").unwrap()
    }

    #[test]
    fn errored_and_non_success_build_info_findings_naming_the_source() {
        let errored = SourceIssue::errored("certificate transparency (crt.sh)")
            .finding("subdomain_recon", &target());
        assert_eq!(errored.status, Status::Info);
        assert_eq!(errored.severity, Severity::Info);
        assert!(errored.title.contains("certificate transparency (crt.sh)"));
        assert!(
            errored
                .description
                .as_deref()
                .unwrap()
                .contains("may be incomplete")
        );
        let ev = errored.evidence.unwrap();
        assert_eq!(ev["source"], "certificate transparency (crt.sh)");
        assert_eq!(ev["status"], serde_json::Value::Null);
        assert_eq!(ev["results_may_be_incomplete"], true);

        let non_success =
            SourceIssue::non_success("registration data (RIPEstat)", 502).finding("x", &target());
        assert!(non_success.title.contains("registration data (RIPEstat)"));
        assert!(non_success.description.as_deref().unwrap().contains("502"));
        assert_eq!(non_success.evidence.unwrap()["status"], 502);
    }

    #[test]
    fn to_findings_dedupes_per_source() {
        // A resolver hit once per candidate fails many times → one finding, and a
        // distinct source is reported separately.
        let issues = vec![
            SourceIssue::errored("DNS-over-HTTPS resolver"),
            SourceIssue::non_success("DNS-over-HTTPS resolver", 500),
            SourceIssue::errored("certificate transparency (crt.sh)"),
        ];
        let findings = to_findings(issues, "subdomain_recon", &target());
        assert_eq!(
            findings.len(),
            2,
            "one finding per distinct source: {findings:#?}"
        );
        // First occurrence per source wins: the resolver's first issue was the
        // transport error (no status).
        let resolver = findings
            .iter()
            .find(|f| f.title.contains("DNS-over-HTTPS resolver"))
            .unwrap();
        assert_eq!(
            resolver.evidence.as_ref().unwrap()["status"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn no_issues_yields_no_findings() {
        assert!(to_findings(Vec::new(), "subdomain_recon", &target()).is_empty());
    }
}
