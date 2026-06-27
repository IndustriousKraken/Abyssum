//! Report generation over the persisted scan record.
//!
//! A [`ReportGenerator`] reads one or more stored sessions (and their findings)
//! through the [persistence](crate::persistence) layer and renders them into one
//! of four output forms — [`Markdown`](ReportFormat::Markdown) submission report,
//! a machine-readable [`Json`](ReportFormat::Json) export, a flat
//! [`Csv`](ReportFormat::Csv) summary, or a [`HackerOne`](ReportFormat::HackerOne)
//! submission. It does no network I/O and never re-scans: a report is a pure
//! function of stored data, so it is deterministic and testable from in-memory
//! fixtures.
//!
//! Two derived ideas live here as *content*, not new scanning behaviour: a
//! per-scanner [remediation](remediation_for) recommendation and an
//! [impact](impact_for) statement, each a static table with a generic fallback. A
//! finding's own `recommendations` field, when present, takes precedence over the
//! remediation table.
//!
//! ## Reportable findings only
//!
//! Every format includes only **reportable** findings — those whose
//! [`Status`](crate::scan::Status) is [`Vulnerable`](crate::scan::Status::Vulnerable)
//! (see [`Status::is_reportable`](crate::scan::Status::is_reportable)) — so a report
//! is never padded with benign or informational probe results.
//!
//! ## "Finding type" is the scanner id
//!
//! A finding carries no separate type field; its *type* is the id of the scanner
//! that produced it (`cors`, `idor`, …). Where a format names both a "scanner id"
//! and a "finding type" column they carry that same value.

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::persistence::DatabaseManager;
use crate::scan::{Finding, ScanSession, SessionStatus, Severity, Status};

/// Which output form a report is rendered in.
///
/// `Markdown` and `HackerOne` describe a single session; `Json` and `Csv` cover
/// one or more sessions together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// A self-contained Markdown submission report.
    Markdown,
    /// A structured, machine-readable JSON export.
    Json,
    /// A flat CSV summary (one row per reportable finding).
    Csv,
    /// A Markdown report shaped to a HackerOne submission.
    HackerOne,
}

/// Knobs that adjust what a report contains.
#[derive(Debug, Clone, Copy)]
pub struct ReportOptions {
    /// Include each finding's evidence (the default). When `false`, evidence
    /// blocks are omitted so a redacted/short report can be produced. CSV is a
    /// summary-only format and carries no evidence regardless.
    pub include_evidence: bool,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            include_evidence: true,
        }
    }
}

/// Renders stored scan sessions into reports. Holds the store it reads from; it
/// performs no other I/O.
#[derive(Debug, Clone)]
pub struct ReportGenerator {
    db: DatabaseManager,
}

impl ReportGenerator {
    /// Build a generator over `db`.
    pub fn new(db: DatabaseManager) -> Self {
        Self { db }
    }

    /// Generate a report for `session_ids` in `format`.
    ///
    /// `Markdown` and `HackerOne` require **exactly one** session id; `Json` and
    /// `Csv` accept one or more. A session id no stored session carries yields
    /// [`Error::NotFound`] and no report is produced. A `HackerOne` export for a
    /// session with no reportable findings yields an error (there is nothing to
    /// report).
    pub async fn generate(
        &self,
        session_ids: &[Uuid],
        format: ReportFormat,
        options: ReportOptions,
    ) -> Result<String> {
        match format {
            ReportFormat::Markdown => {
                let session = self.load_single(session_ids).await?;
                Ok(render_markdown(&session, options))
            }
            ReportFormat::HackerOne => {
                let session = self.load_single(session_ids).await?;
                render_hackerone(&session, options)
            }
            ReportFormat::Json => {
                let sessions = self.load_many(session_ids).await?;
                render_json(&sessions, options)
            }
            ReportFormat::Csv => {
                let sessions = self.load_many(session_ids).await?;
                Ok(render_csv(&sessions))
            }
        }
    }

    /// Load the one session a single-session format addresses, rejecting an empty
    /// or multi-id selection.
    async fn load_single(&self, ids: &[Uuid]) -> Result<ScanSession> {
        match ids {
            [id] => self.load_one(*id).await,
            [] => Err(Error::Other(
                "a report requires a session identifier".to_string(),
            )),
            _ => Err(Error::Other(
                "the markdown and hackerone formats accept exactly one session identifier"
                    .to_string(),
            )),
        }
    }

    /// Load every session a multi-session format addresses, in the order given.
    async fn load_many(&self, ids: &[Uuid]) -> Result<Vec<ScanSession>> {
        if ids.is_empty() {
            return Err(Error::Other(
                "a report requires at least one session identifier".to_string(),
            ));
        }
        let mut sessions = Vec::with_capacity(ids.len());
        for &id in ids {
            sessions.push(self.load_one(id).await?);
        }
        Ok(sessions)
    }

    /// Load one session (with its findings), mapping an absent id to
    /// [`Error::NotFound`].
    async fn load_one(&self, id: Uuid) -> Result<ScanSession> {
        self.db
            .get_session(id)
            .await?
            .ok_or_else(|| Error::NotFound(format!("no scan session with id {id}")))
    }
}

// --- Shared selection / ordering helpers ----------------------------------

/// The reportable findings of `session`, ordered most-severe-first.
///
/// Filtering keeps only [`Status::Vulnerable`] findings; the stable sort keeps the
/// stored order (timestamp, then id) for equal severities, so ties break
/// deterministically and the output is reproducible.
fn reportable_most_severe_first(session: &ScanSession) -> Vec<&Finding> {
    let mut findings: Vec<&Finding> = session
        .findings
        .iter()
        .filter(|f| f.status.is_reportable())
        .collect();
    findings.sort_by_key(|f| std::cmp::Reverse(severity_rank(f.severity)));
    findings
}

/// Rank a severity for most-severe-first ordering: critical (4) highest, info (0)
/// lowest. This is the natural [`Severity`] order, named so report-layer ordering
/// reads explicitly at the call site.
fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Info => 0,
    }
}

/// The per-severity counts of `findings`, listed critical-first (every level
/// present, zero when none) for the executive-summary breakdown.
fn severity_breakdown(findings: &[&Finding]) -> Vec<(Severity, usize)> {
    [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .into_iter()
    .map(|sev| (sev, findings.iter().filter(|f| f.severity == sev).count()))
    .collect()
}

/// The title-case display label for a severity (human reports).
fn severity_label(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

/// The lowercase wire spelling of a severity (CSV cells), matching the shared
/// serde vocabulary.
fn severity_wire(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// The targets a session covers, joined for the report header.
fn targets_display(session: &ScanSession) -> String {
    if session.targets.is_empty() {
        return "(none)".to_string();
    }
    session
        .targets
        .iter()
        .map(|t| t.full_url().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The session's scan date — when it finished, else when it started, else unknown.
fn scan_date(session: &ScanSession) -> String {
    session
        .finished_at
        .or(session.started_at)
        .map(|dt| dt.to_rfc3339_opts(SecondsFormat::Secs, true))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Pretty-print structured evidence for a fenced code block, falling back to its
/// compact form if it somehow will not pretty-print.
fn pretty_evidence(evidence: &serde_json::Value) -> String {
    serde_json::to_string_pretty(evidence).unwrap_or_else(|_| evidence.to_string())
}

// --- Built-in content tables ----------------------------------------------

/// The remediation text for a finding: its own `recommendations` field when set,
/// otherwise the per-scanner table entry (or the generic fallback).
fn remediation(finding: &Finding) -> &str {
    finding
        .recommendations
        .as_deref()
        .unwrap_or_else(|| remediation_for(&finding.scanner_id))
}

/// The remediation recommendation for a producing scanner id, with a generic
/// fallback for an unknown type.
fn remediation_for(scanner_id: &str) -> &'static str {
    match scanner_id {
        "rest_discovery" => {
            "Remove or protect undocumented and unintended endpoints, and ensure every \
             exposed route requires appropriate authentication and authorization."
        }
        "openapi_discovery" => {
            "Restrict access to API specification and documentation endpoints in production, \
             or ensure they describe only intentionally public surface."
        }
        "cors" => {
            "Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted origins \
             and never combine a wildcard origin with credentialed requests."
        }
        "bac" => {
            "Enforce server-side authorization checks on every sensitive endpoint; never rely \
             on the client hiding or omitting privileged routes."
        }
        "idor" => {
            "Enforce per-object authorization so a user can only access references they own; \
             prefer unpredictable identifiers and validate ownership on every request."
        }
        "graphql" => {
            "Disable introspection in production where appropriate, enforce query depth and \
             complexity limits, and apply field-level authorization."
        }
        _ => {
            "Review the affected endpoint and apply appropriate authentication, authorization, \
             and input-validation controls."
        }
    }
}

/// The impact statement for a producing scanner id, with a generic fallback for an
/// unknown type.
fn impact_for(scanner_id: &str) -> &'static str {
    match scanner_id {
        "rest_discovery" => {
            "Undocumented or unintended endpoints widen the attack surface and may expose \
             functionality or data that was never meant to be reachable."
        }
        "openapi_discovery" => {
            "An exposed API specification reveals the full endpoint map, parameters, and \
             schemas, giving an attacker a precise blueprint of the API."
        }
        "cors" => {
            "A permissive CORS policy can let a malicious site read authenticated responses on \
             behalf of a victim, leading to data theft or unwanted account actions."
        }
        "bac" => {
            "Broken access control lets an unauthorized user reach functionality or data \
             restricted to other roles, up to full administrative compromise."
        }
        "idor" => {
            "An insecure direct object reference lets an attacker read or modify other users' \
             records simply by changing an identifier."
        }
        "graphql" => {
            "An over-permissive GraphQL endpoint can leak the full schema and allow expensive \
             or unauthorized queries against sensitive fields."
        }
        _ => {
            "This finding may allow unauthorized access to functionality or data; assess the \
             affected endpoint and its exposure."
        }
    }
}

// --- Markdown -------------------------------------------------------------

/// Render a single session as a self-contained Markdown submission report.
fn render_markdown(session: &ScanSession, options: ReportOptions) -> String {
    let findings = reportable_most_severe_first(session);
    let mut out = String::new();

    out.push_str("# Abyssum Scan Report\n\n");
    out.push_str(&format!("- **Target:** {}\n", targets_display(session)));
    out.push_str(&format!("- **Scan date:** {}\n", scan_date(session)));
    out.push_str(&format!(
        "- **Scanners:** {}\n",
        if session.scanner_ids.is_empty() {
            "(none)".to_string()
        } else {
            session.scanner_ids.join(", ")
        }
    ));
    out.push_str(&format!("- **Session:** {}\n\n", session.id));

    out.push_str("## Executive Summary\n\n");
    out.push_str(&format!("Total findings: {}\n\n", findings.len()));
    out.push_str("| Severity | Count |\n| --- | --- |\n");
    for (sev, count) in severity_breakdown(&findings) {
        out.push_str(&format!("| {} | {} |\n", severity_label(sev), count));
    }
    out.push('\n');

    out.push_str("## Findings\n\n");
    if findings.is_empty() {
        out.push_str("_No reportable findings._\n");
    }
    for (i, finding) in findings.iter().enumerate() {
        out.push_str(&format!(
            "### {}. {} — {}\n\n",
            i + 1,
            finding.title,
            severity_label(finding.severity)
        ));
        out.push_str(&format!("- **Type:** {}\n", finding.scanner_id));
        out.push_str(&format!(
            "- **Severity:** {}\n",
            severity_label(finding.severity)
        ));
        out.push_str(&format!(
            "- **Endpoint:** {}\n\n",
            finding.target.full_url()
        ));
        if let Some(description) = &finding.description {
            out.push_str(description);
            out.push_str("\n\n");
        }
        if options.include_evidence {
            if let Some(evidence) = &finding.evidence {
                out.push_str("**Evidence:**\n\n```json\n");
                out.push_str(&pretty_evidence(evidence));
                out.push_str("\n```\n\n");
            }
        }
        out.push_str(&format!("**Remediation:** {}\n\n", remediation(finding)));
    }
    out
}

// --- JSON -----------------------------------------------------------------

/// The top-level JSON export object.
#[derive(Serialize)]
struct JsonExport {
    export_timestamp: String,
    session_count: usize,
    sessions: Vec<JsonSession>,
}

/// One session's metadata and reportable findings in the JSON export.
#[derive(Serialize)]
struct JsonSession {
    session_id: Uuid,
    targets: Vec<String>,
    scanner_ids: Vec<String>,
    status: SessionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    started_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    finished_at: Option<DateTime<Utc>>,
    findings: Vec<JsonFinding>,
}

/// One reportable finding in the JSON export. `type` is the producing scanner id.
#[derive(Serialize)]
struct JsonFinding {
    #[serde(rename = "type")]
    finding_type: String,
    severity: Severity,
    target: String,
    status: Status,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<serde_json::Value>,
}

/// Render one or more sessions as a structured JSON export.
fn render_json(sessions: &[ScanSession], options: ReportOptions) -> Result<String> {
    let export = JsonExport {
        export_timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        session_count: sessions.len(),
        sessions: sessions.iter().map(|s| json_session(s, options)).collect(),
    };
    let mut json = serde_json::to_string_pretty(&export)
        .map_err(|e| Error::Other(format!("failed to render JSON report: {e}")))?;
    json.push('\n');
    Ok(json)
}

fn json_session(session: &ScanSession, options: ReportOptions) -> JsonSession {
    JsonSession {
        session_id: session.id,
        targets: session
            .targets
            .iter()
            .map(|t| t.full_url().to_string())
            .collect(),
        scanner_ids: session.scanner_ids.clone(),
        status: session.status,
        started_at: session.started_at,
        finished_at: session.finished_at,
        findings: session
            .findings
            .iter()
            .filter(|f| f.status.is_reportable())
            .map(|f| json_finding(f, options))
            .collect(),
    }
}

fn json_finding(finding: &Finding, options: ReportOptions) -> JsonFinding {
    JsonFinding {
        finding_type: finding.scanner_id.clone(),
        severity: finding.severity,
        target: finding.target.full_url().to_string(),
        status: finding.status,
        title: finding.title.clone(),
        description: finding.description.clone(),
        evidence: if options.include_evidence {
            finding.evidence.clone()
        } else {
            None
        },
    }
}

// --- CSV ------------------------------------------------------------------

/// The stable CSV header. `scanner_id` and `finding_type` carry the same value —
/// a finding's type is the id of the scanner that produced it (see module docs).
const CSV_HEADER: &str = "session,target,scanner_id,finding_type,severity,endpoint,description";

/// Render one or more sessions as a flat CSV summary: a header row plus one row per
/// reportable finding across the sessions.
fn render_csv(sessions: &[ScanSession]) -> String {
    let mut out = String::new();
    out.push_str(CSV_HEADER);
    out.push('\n');
    for session in sessions {
        for finding in session.findings.iter().filter(|f| f.status.is_reportable()) {
            let row = [
                session.id.to_string(),
                finding.target.base_url().to_string(),
                finding.scanner_id.clone(),
                finding.scanner_id.clone(),
                severity_wire(finding.severity).to_string(),
                finding.target.full_url().to_string(),
                finding.description.clone().unwrap_or_default(),
            ];
            let escaped: Vec<String> = row.iter().map(|c| csv_escape(c)).collect();
            out.push_str(&escaped.join(","));
            out.push('\n');
        }
    }
    out
}

/// Escape a CSV field per RFC 4180: wrap in double quotes (doubling any interior
/// quote) when it contains a comma, quote, or line break; otherwise emit verbatim.
fn csv_escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

// --- HackerOne ------------------------------------------------------------

/// Render a single session as a HackerOne-shaped submission, built around its
/// most-severe finding. Errors when the session has no reportable findings.
fn render_hackerone(session: &ScanSession, options: ReportOptions) -> Result<String> {
    let findings = reportable_most_severe_first(session);
    let Some((lead, rest)) = findings.split_first() else {
        return Err(Error::Other(format!(
            "session {} has no reportable findings to report",
            session.id
        )));
    };

    let mut out = String::new();
    out.push_str(&format!("# {}\n\n", lead.title));

    out.push_str("## Summary\n\n");
    out.push_str(&format!(
        "**Severity:** {}\n\n",
        severity_label(lead.severity)
    ));
    match &lead.description {
        Some(description) => {
            out.push_str(description);
            out.push_str("\n\n");
        }
        None => out.push_str(&format!(
            "A `{}` finding was identified at {}.\n\n",
            lead.scanner_id,
            lead.target.full_url()
        )),
    }

    out.push_str("## Steps To Reproduce\n\n");
    out.push_str(&steps_to_reproduce(lead, options.include_evidence));
    out.push_str("\n\n");

    out.push_str("## Impact\n\n");
    out.push_str(impact_for(&lead.scanner_id));
    out.push_str("\n\n");

    out.push_str("## Supporting Material\n\n");
    if options.include_evidence {
        match &lead.evidence {
            Some(evidence) => {
                out.push_str("```json\n");
                out.push_str(&pretty_evidence(evidence));
                out.push_str("\n```\n\n");
            }
            None => out.push_str("_No additional evidence captured._\n\n"),
        }
    } else {
        out.push_str("_Evidence omitted from this report._\n\n");
    }
    out.push_str(&format!("**Remediation:** {}\n\n", remediation(lead)));

    if !rest.is_empty() {
        out.push_str("## Additional Findings\n\n");
        for finding in rest {
            out.push_str(&format!(
                "- **{}** (`{}`, {}) — {}\n",
                finding.title,
                finding.scanner_id,
                severity_label(finding.severity),
                finding.target.full_url()
            ));
        }
        out.push('\n');
    }
    Ok(out)
}

/// Detection steps for a finding — how to *re-observe* it, never how to exploit it
/// (Abyssum detects, it does not weaponize). Derived from the finding's evidence
/// when present and evidence is included; otherwise a generic re-run instruction.
fn steps_to_reproduce(finding: &Finding, include_evidence: bool) -> String {
    let endpoint = finding.target.full_url();
    if include_evidence {
        if let Some(evidence) = &finding.evidence {
            let request = match evidence.get("method").and_then(|m| m.as_str()) {
                Some(method) => format!("1. Send a `{method}` request to `{endpoint}`."),
                None => format!("1. Send a request to `{endpoint}`."),
            };
            return format!(
                "{request}\n2. Observe the response — the `{}` check flags: {}.",
                finding.scanner_id, finding.title
            );
        }
    }
    format!(
        "Re-run the `{}` check against `{endpoint}` to re-observe this issue.",
        finding.scanner_id
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::Target;

    fn target(url: &str) -> Target {
        Target::parse(url).unwrap()
    }

    /// A fixture session: four findings spanning severities plus two non-reportable
    /// results (a safe check and an informational observation) that every format
    /// must exclude. One description carries a comma, quote, and newline to exercise
    /// CSV escaping.
    fn fixture() -> ScanSession {
        let mut session = ScanSession::new(
            vec![target("https://api.example.com")],
            vec!["cors".into(), "idor".into(), "bac".into(), "graphql".into()],
        );
        session.findings = vec![
            Finding::builder("cors", target("https://api.example.com"), "Permissive CORS")
                .severity(Severity::High)
                .status(Status::Vulnerable)
                .description(
                    "Reflects arbitrary Origin, with \"credentials\" allowed,\nincluding null.",
                )
                .evidence(serde_json::json!({ "method": "GET", "origin": "https://evil.test" }))
                .build(),
            Finding::builder(
                "bac",
                target("https://api.example.com").with_path("/admin"),
                "Admin reachable without auth",
            )
            .severity(Severity::Critical)
            .status(Status::Vulnerable)
            .description("The admin panel responds 200 with no session.")
            .build(),
            Finding::builder(
                "idor",
                target("https://api.example.com").with_path("/users/1"),
                "Enumerable user reference",
            )
            .severity(Severity::Medium)
            .status(Status::Vulnerable)
            .recommendations("Custom: scope every record to its owner.")
            .build(),
            Finding::builder(
                "graphql",
                target("https://api.example.com"),
                "Introspection enabled",
            )
            .severity(Severity::Low)
            .status(Status::Vulnerable)
            .build(),
            // Non-reportable: a checked-and-sound result and a neutral observation.
            Finding::builder(
                "cors",
                target("https://api.example.com"),
                "CORS locked down",
            )
            .severity(Severity::Info)
            .status(Status::Safe)
            .build(),
            Finding::builder(
                "rest_discovery",
                target("https://api.example.com"),
                "Endpoint observed",
            )
            .status(Status::Info)
            .build(),
        ];
        session
    }

    /// The four reportable titles; the two non-reportable ones must never appear.
    const REPORTABLE_TITLES: [&str; 4] = [
        "Permissive CORS",
        "Admin reachable without auth",
        "Enumerable user reference",
        "Introspection enabled",
    ];
    const NON_REPORTABLE_TITLES: [&str; 2] = ["CORS locked down", "Endpoint observed"];

    // -- Markdown ----------------------------------------------------------

    #[test]
    fn markdown_has_header_summary_and_each_finding() {
        let md = render_markdown(&fixture(), ReportOptions::default());

        // Header metadata.
        assert!(md.contains("https://api.example.com/"), "missing target");
        assert!(md.contains("**Session:**"), "missing session id label");
        assert!(
            md.contains("cors, idor, bac, graphql"),
            "missing scanner ids"
        );

        // Executive summary: total + per-severity breakdown counts.
        assert!(md.contains("Total findings: 4"));
        assert!(md.contains("| Critical | 1 |"));
        assert!(md.contains("| High | 1 |"));
        assert!(md.contains("| Medium | 1 |"));
        assert!(md.contains("| Low | 1 |"));
        assert!(md.contains("| Info | 0 |"));

        // Each reportable finding's type, severity, endpoint, and a remediation.
        for title in REPORTABLE_TITLES {
            assert!(md.contains(title), "markdown missing finding {title:?}");
        }
        assert!(md.contains("- **Type:** bac"));
        assert!(md.contains("- **Endpoint:** https://api.example.com/admin"));
        assert!(md.contains("**Remediation:**"));
        // The per-scanner remediation table is applied...
        assert!(
            md.contains("Restrict Access-Control-Allow-Origin"),
            "cors remediation text from the table"
        );
        // ...but a finding's own recommendation takes precedence.
        assert!(md.contains("Custom: scope every record to its owner."));
    }

    #[test]
    fn markdown_orders_findings_most_severe_first() {
        let md = render_markdown(&fixture(), ReportOptions::default());
        let crit = md.find("Admin reachable without auth").unwrap();
        let high = md.find("Permissive CORS").unwrap();
        let medium = md.find("Enumerable user reference").unwrap();
        let low = md.find("Introspection enabled").unwrap();
        assert!(
            crit < high && high < medium && medium < low,
            "not most-severe-first"
        );
    }

    #[test]
    fn markdown_evidence_toggles_with_the_option() {
        let with = render_markdown(
            &fixture(),
            ReportOptions {
                include_evidence: true,
            },
        );
        assert!(with.contains("**Evidence:**"));
        assert!(with.contains("evil.test"));

        let without = render_markdown(
            &fixture(),
            ReportOptions {
                include_evidence: false,
            },
        );
        assert!(!without.contains("**Evidence:**"));
        assert!(!without.contains("evil.test"));
        // Type/severity/description still present with evidence off.
        assert!(without.contains("Permissive CORS"));
        assert!(without.contains("- **Severity:** High"));
        assert!(without.contains("Reflects arbitrary Origin"));
    }

    // -- CSV ---------------------------------------------------------------

    #[test]
    fn csv_has_header_one_row_per_reportable_finding_and_escapes() {
        let csv = render_csv(std::slice::from_ref(&fixture()));
        let mut lines = csv.lines();
        assert_eq!(lines.next().unwrap(), CSV_HEADER);

        // The escaped comma/quote/newline description spans the field but stays
        // well-formed; re-parsing recovers exactly header + 4 data rows.
        let records = parse_csv(&csv);
        assert_eq!(
            records.len(),
            REPORTABLE_TITLES.len() + 1,
            "header + one row each"
        );
        // The CORS row's description round-trips its special characters.
        let cors_row = records
            .iter()
            .find(|r| r[2] == "cors")
            .expect("a cors data row");
        assert_eq!(cors_row.len(), 7, "seven columns");
        assert_eq!(cors_row[3], "cors", "finding_type equals scanner_id");
        assert_eq!(cors_row[4], "high");
        assert!(cors_row[6].contains("\"credentials\""));
        assert!(cors_row[6].contains('\n'));
    }

    #[test]
    fn csv_excludes_non_reportable_findings() {
        let csv = render_csv(std::slice::from_ref(&fixture()));
        for title in NON_REPORTABLE_TITLES {
            assert!(!csv.contains(title), "csv leaked non-reportable {title:?}");
        }
    }

    // -- JSON --------------------------------------------------------------

    #[test]
    fn json_export_carries_sessions_and_finding_fields() {
        let a = fixture();
        let mut b = ScanSession::new(vec![target("https://b.example.com")], vec!["cors".into()]);
        b.findings = vec![
            Finding::builder("cors", target("https://b.example.com"), "Other CORS")
                .severity(Severity::High)
                .status(Status::Vulnerable)
                .build(),
        ];

        let json = render_json(&[a.clone(), b.clone()], ReportOptions::default()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Two sessions, with a count and a separate entry each (task 4.1/4.3).
        assert_eq!(value["session_count"], 2);
        assert!(value["export_timestamp"].is_string());
        let sessions = value["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 2);

        // First session's metadata and reportable finding fields.
        let s0 = &sessions[0];
        assert_eq!(s0["session_id"], a.id.to_string());
        assert_eq!(s0["targets"][0], "https://api.example.com/");
        let findings = s0["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 4, "only reportable findings");
        let cors = findings
            .iter()
            .find(|f| f["title"] == "Permissive CORS")
            .unwrap();
        assert_eq!(cors["type"], "cors");
        assert_eq!(cors["severity"], "high");
        assert_eq!(cors["status"], "vulnerable");
        assert_eq!(cors["target"], "https://api.example.com/");
        assert!(cors["evidence"]["origin"] == "https://evil.test");
    }

    #[test]
    fn json_omits_evidence_when_disabled_and_excludes_non_reportable() {
        let json = render_json(
            std::slice::from_ref(&fixture()),
            ReportOptions {
                include_evidence: false,
            },
        )
        .unwrap();
        assert!(
            !json.contains("evil.test"),
            "evidence leaked with option off"
        );
        for title in NON_REPORTABLE_TITLES {
            assert!(
                !json.contains(title),
                "json leaked non-reportable {title:?}"
            );
        }
        // Still carries the finding's other fields.
        assert!(json.contains("Permissive CORS"));
    }

    // -- HackerOne ---------------------------------------------------------

    #[test]
    fn hackerone_leads_with_most_severe_and_has_all_sections() {
        let h1 = render_hackerone(&fixture(), ReportOptions::default()).unwrap();
        // Leads with the critical finding's title.
        assert!(h1.starts_with("# Admin reachable without auth"));
        assert!(h1.contains("## Summary"));
        assert!(h1.contains("## Steps To Reproduce"));
        assert!(h1.contains("## Impact"));
        assert!(h1.contains("## Supporting Material"));
        // The remaining findings are listed.
        assert!(h1.contains("## Additional Findings"));
        assert!(h1.contains("Permissive CORS"));
        assert!(h1.contains("Introspection enabled"));
        // Non-reportable results never appear.
        for title in NON_REPORTABLE_TITLES {
            assert!(
                !h1.contains(title),
                "hackerone leaked non-reportable {title:?}"
            );
        }
    }

    #[test]
    fn hackerone_evidence_toggle_and_steps_fallback() {
        // Lead (bac/critical) carries no evidence → generic re-run instruction.
        let h1 = render_hackerone(&fixture(), ReportOptions::default()).unwrap();
        assert!(h1.contains("Re-run the `bac` check"));

        // With evidence off, no evidence content leaks.
        let redacted = render_hackerone(
            &fixture(),
            ReportOptions {
                include_evidence: false,
            },
        )
        .unwrap();
        assert!(redacted.contains("Evidence omitted from this report."));
        assert!(!redacted.contains("evil.test"));
    }

    #[test]
    fn hackerone_errors_when_no_reportable_findings() {
        let mut session =
            ScanSession::new(vec![target("https://x.example.com")], vec!["cors".into()]);
        session.findings = vec![
            Finding::builder("cors", target("https://x.example.com"), "Safe")
                .status(Status::Safe)
                .build(),
        ];
        let err = render_hackerone(&session, ReportOptions::default()).unwrap_err();
        assert!(
            matches!(err, Error::Other(_)),
            "expected nothing-to-report error, got {err:?}"
        );
    }

    // A minimal RFC 4180 CSV parser for the escaping assertions.
    fn parse_csv(input: &str) -> Vec<Vec<String>> {
        let mut records = Vec::new();
        let mut record = Vec::new();
        let mut field = String::new();
        let mut in_quotes = false;
        let mut chars = input.chars().peekable();
        while let Some(c) = chars.next() {
            if in_quotes {
                match c {
                    '"' if chars.peek() == Some(&'"') => {
                        chars.next();
                        field.push('"');
                    }
                    '"' => in_quotes = false,
                    other => field.push(other),
                }
            } else {
                match c {
                    '"' => in_quotes = true,
                    ',' => record.push(std::mem::take(&mut field)),
                    '\n' => {
                        record.push(std::mem::take(&mut field));
                        records.push(std::mem::take(&mut record));
                    }
                    '\r' => {}
                    other => field.push(other),
                }
            }
        }
        if !field.is_empty() || !record.is_empty() {
            record.push(field);
            records.push(record);
        }
        records
    }
}
