//! The REST endpoint discovery scanner.
//!
//! This is the foundational reconnaissance scanner and the template the other five
//! follow. It probes a target's origin against a curated wordlist (seeded by
//! `add-seed-data`), classifies each response, and reports the paths that
//! correspond to real endpoints — distinguishing openly accessible endpoints from
//! protected ones.
//!
//! Every request goes through [`ScanContext::send`], the engine's only outbound
//! path, so pacing (the configured floor), the rotating User-Agent, cancellation,
//! and progress all apply uniformly — the scanner owns none of them and cannot
//! probe faster than the floor.
//!
//! ## Soft-404 baseline
//!
//! Many targets answer unknown paths with a *200 and a not-found body* (a
//! "soft-404"). Before probing the wordlist the scanner sends one request to a
//! random, unlikely path and fingerprints the response (status + a hash and length
//! of the whitespace-normalized body). A candidate whose response is
//! indistinguishable from that baseline is classified **absent** and never
//! reported, so a catch-all target does not yield a finding for every path.

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::header::CONTENT_TYPE;
use serde_json::json;
use url::Url;
use uuid::Uuid;

use abyssum_core::{
    BaseScanner, Error, Finding, ProgressUpdate, RequestSpec, Result, ScanContext, Severity,
    Status, Target,
};

use crate::wordlist::WordlistProvider;

/// The two seeded lists this scanner draws candidates from (see the change's
/// design). Both are looked up by name and merged into one flat candidate set; a
/// base × endpoint cross-product is deliberately *not* done, because it multiplies
/// request volume and conflicts with Abyssum's pacing-floor identity.
const ENDPOINT_LIST: &str = "rest_endpoints";
const API_BASES_LIST: &str = "rest_api_bases";

/// Path fragments that make an *accessible* endpoint noteworthy rather than
/// benign. A discovered, accessible endpoint whose path contains one of these is
/// reported as [`Status::Vulnerable`] (a notable exposed surface) instead of a
/// neutral observation. Protected endpoints are unaffected — auth in front of a
/// sensitive path is the desired state.
const SENSITIVE_MARKERS: &[&str] = &[
    "admin",
    "internal",
    "debug",
    "actuator",
    "secret",
    "private",
    "credential",
    "backup",
    ".env",
    "phpinfo",
];

/// Probes a target's origin against a curated endpoint wordlist.
pub struct RestDiscoveryScanner {
    wordlists: Arc<dyn WordlistProvider>,
}

impl RestDiscoveryScanner {
    /// The stable scanner id the registry keys on and a scan selects by.
    pub const ID: &'static str = "rest_discovery";
    /// The human-readable name surfaces display.
    pub const NAME: &'static str = "REST endpoint discovery";
    /// A human-readable description of what the scanner checks.
    pub const DESCRIPTION: &'static str =
        "Probes a target's base URL against a curated endpoint wordlist to discover \
         undocumented or hidden API endpoints, classifying each as accessible or protected.";

    /// Build the scanner over a wordlist source. In production the source is the
    /// seeded [`SeedStore`](abyssum_core::SeedStore); tests pass an in-memory list.
    pub fn new(wordlists: Arc<dyn WordlistProvider>) -> Self {
        Self { wordlists }
    }

    /// Load the candidate paths once per scan run: union the two seeded lists,
    /// normalize each to a single leading slash, and dedupe (first occurrence
    /// wins), preserving order.
    pub async fn candidate_paths(&self) -> Result<Vec<String>> {
        let mut seen = HashSet::new();
        let mut candidates = Vec::new();
        for list in [ENDPOINT_LIST, API_BASES_LIST] {
            for raw in self.wordlists.wordlist(list).await? {
                if let Some(path) = normalize_path(&raw) {
                    if seen.insert(path.clone()) {
                        candidates.push(path);
                    }
                }
            }
        }
        Ok(candidates)
    }

    /// Fingerprint the target's not-found behaviour from one request to a random,
    /// unlikely path. Best-effort: a failed baseline probe disables soft-404
    /// suppression (returns `None`) rather than aborting the scan.
    async fn probe_baseline(&self, target: &Target, ctx: &ScanContext) -> Option<Baseline> {
        let probe_path = format!("/abyssum-probe-{}", Uuid::new_v4().simple());
        let url = candidate_url(target.base_url(), &probe_path);
        match self.probe(ctx, &url).await {
            Ok(observed) => Some(Baseline {
                status: observed.status,
                body_hash: observed.body_hash,
                body_len: observed.body_len,
            }),
            Err(_) => None,
        }
    }

    /// Issue one paced GET and read back the salient signals for classification.
    async fn probe(&self, ctx: &ScanContext, url: &Url) -> Result<Observed> {
        let response = ctx.send(RequestSpec::get(url.clone())).await?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = response
            .text()
            .await
            .map_err(|e| Error::Http(format!("failed to read response body from {url}: {e}")))?;
        let normalized = normalize_body(&body);
        Ok(Observed {
            status,
            body_hash: hash_str(&normalized),
            body_len: normalized.len(),
            api_shaped: is_api_shaped(content_type.as_deref(), &body),
            content_type,
        })
    }
}

#[async_trait]
impl BaseScanner for RestDiscoveryScanner {
    fn id(&self) -> &str {
        Self::ID
    }

    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        Self::DESCRIPTION
    }

    async fn scan(&self, target: &Target, ctx: &ScanContext) -> Result<Vec<Finding>> {
        let candidates = self.candidate_paths().await?;
        let total = candidates.len();
        let mut findings = Vec::new();
        if total == 0 {
            return Ok(findings);
        }

        // Honour cancellation before issuing any traffic.
        if ctx.is_cancelled() {
            return Ok(findings);
        }

        // Establish the soft-404 baseline before probing the wordlist.
        let baseline = self.probe_baseline(target, ctx).await;

        for (index, path) in candidates.iter().enumerate() {
            // Stop promptly on cancellation, returning the findings gathered so
            // far. Breaking (not erroring) preserves the partial result.
            if ctx.is_cancelled() {
                break;
            }

            let url = candidate_url(target.base_url(), path);
            // A transport or pacing error on one candidate is not fatal: the
            // candidate simply yields no finding and the scan continues.
            if let Ok(observed) = self.probe(ctx, &url).await {
                if let Some(finding) =
                    finding_for(target, self.id(), path, &observed, baseline.as_ref())
                {
                    findings.push(finding);
                }
            }

            // Report progress after each candidate is tested (success or not).
            ctx.report_progress(
                ProgressUpdate::new(self.id(), index + 1, total)
                    .current_item(path.clone())
                    .message(format!("probed {}/{total}", index + 1)),
            );
        }

        Ok(findings)
    }
}

/// How a probed path's response is read.
///
/// `Accessible` and `Protected` are reportable discoveries; `Erroring` is a
/// low-confidence discovery (the host errored); `Absent` is not reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Classification {
    /// A real, openly accessible endpoint (a 2xx distinct from the baseline).
    Accessible,
    /// A real endpoint that requires authentication/authorization (401/403).
    Protected,
    /// A path the server errored on (5xx); existence is low-confidence.
    Erroring,
    /// No endpoint: a not-found, a soft-404, or an uninteresting status.
    Absent,
}

impl Classification {
    /// A stable lowercase label for the finding evidence.
    fn as_str(self) -> &'static str {
        match self {
            Classification::Accessible => "accessible",
            Classification::Protected => "protected",
            Classification::Erroring => "erroring",
            Classification::Absent => "absent",
        }
    }
}

/// The fingerprint of a "definitely absent" response, learned from the baseline
/// probe. A candidate matching this is a soft-404.
#[derive(Debug, Clone, Copy)]
struct Baseline {
    status: u16,
    body_hash: u64,
    body_len: usize,
}

impl Baseline {
    /// Whether `observed` is indistinguishable from this not-found baseline: the
    /// same status and either an equal normalized-body hash (a static soft-404) or
    /// a closely-matching body length for substantial bodies (a dynamic soft-404
    /// that echoes the path but is otherwise the same error page).
    fn matches(&self, observed: &Observed) -> bool {
        self.status == observed.status
            && (self.body_hash == observed.body_hash
                || bodies_similar(self.body_len, observed.body_len))
    }
}

/// The salient signals read from one probed response.
#[derive(Debug, Clone)]
struct Observed {
    status: u16,
    body_hash: u64,
    body_len: usize,
    api_shaped: bool,
    content_type: Option<String>,
}

/// Classify a probed response against the (optional) soft-404 baseline.
fn classify(observed: &Observed, baseline: Option<&Baseline>) -> Classification {
    // A response indistinguishable from the not-found baseline is absent, whatever
    // its status — this is what suppresses soft-404s (and a whole-site auth wall).
    if let Some(baseline) = baseline {
        if baseline.matches(observed) {
            return Classification::Absent;
        }
    }

    let status = observed.status;
    if (200..300).contains(&status) {
        Classification::Accessible
    } else if status == 401 || status == 403 {
        Classification::Protected
    } else if (500..600).contains(&status) {
        Classification::Erroring
    } else {
        // 404 and other not-found / redirect / uninteresting statuses.
        Classification::Absent
    }
}

/// Build a [`Finding`] for a classified candidate, or `None` when the path is
/// absent (not reported). Maps the scanner-specific classification onto the
/// canonical [`Status`]/[`Severity`] vocabulary; the "accessible"/"protected"
/// labels live in the title and evidence, never as new status values.
fn finding_for(
    target: &Target,
    scanner_id: &str,
    path: &str,
    observed: &Observed,
    baseline: Option<&Baseline>,
) -> Option<Finding> {
    let classification = classify(observed, baseline);

    let (status, severity, title, recommendation) = match classification {
        Classification::Absent => return None,
        Classification::Accessible if is_sensitive(path) => (
            Status::Vulnerable,
            Severity::Medium,
            format!("Sensitive endpoint accessible without authentication: {path}"),
            Some("Require authentication/authorization on this endpoint or remove it from the exposed surface."),
        ),
        Classification::Accessible => (
            Status::Info,
            Severity::Info,
            format!("Accessible endpoint discovered: {path}"),
            None,
        ),
        Classification::Protected => (
            Status::Safe,
            Severity::Info,
            format!("Protected endpoint discovered: {path}"),
            None,
        ),
        Classification::Erroring => (
            Status::Info,
            Severity::Info,
            format!("Endpoint returned a server error: {path}"),
            None,
        ),
    };

    let evidence = json!({
        "path": path,
        "status": observed.status,
        "classification": classification.as_str(),
        "content_type": observed.content_type,
        "api_shaped": observed.api_shaped,
        "response_bytes": observed.body_len,
    });

    let mut builder = Finding::builder(scanner_id, target.clone(), title)
        .severity(severity)
        .status(status)
        .description(describe(classification, observed))
        .evidence(evidence);
    if let Some(recommendation) = recommendation {
        builder = builder.recommendations(recommendation);
    }
    Some(builder.build())
}

/// A human-readable description for a classified finding.
fn describe(classification: Classification, observed: &Observed) -> String {
    let content_type = observed.content_type.as_deref().unwrap_or("none");
    match classification {
        Classification::Accessible => format!(
            "Responded with HTTP {} (content-type: {content_type}), distinct from the \
             not-found baseline.",
            observed.status
        ),
        Classification::Protected => format!(
            "Responded with HTTP {} — the endpoint exists but requires authentication or \
             authorization.",
            observed.status
        ),
        Classification::Erroring => format!(
            "Responded with HTTP {} (server error); the endpoint may exist but this is \
             low-confidence.",
            observed.status
        ),
        Classification::Absent => String::new(),
    }
}

/// Whether an accessible path looks sensitive enough to flag as an exposed surface.
fn is_sensitive(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    SENSITIVE_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// Normalize a raw wordlist entry to a single-leading-slash path, or `None` if it
/// is blank or only slashes (the bare origin is not a discovery candidate).
fn normalize_path(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_leading = trimmed.trim_start_matches('/');
    if without_leading.is_empty() {
        return None;
    }
    Some(format!("/{without_leading}"))
}

/// Build the candidate URL: the target's origin with its path replaced by the
/// candidate, and any base query/fragment dropped. Discovery is origin-relative.
fn candidate_url(base: &Url, path: &str) -> Url {
    let mut url = base.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    url
}

/// Collapse all runs of whitespace to single spaces and trim, so trivially
/// reformatted not-found bodies fingerprint identically.
fn normalize_body(body: &str) -> String {
    body.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A stable hash of a (normalized) string for body fingerprinting.
fn hash_str(value: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

/// Minimum normalized-body length for the length-similarity branch of soft-404
/// matching to apply. Below this, two short but genuinely different bodies can
/// coincidentally share a length, so only an exact (hash) match counts as a
/// soft-404 — the length branch exists for substantial, dynamic error pages.
const MIN_SIMILAR_BODY_LEN: usize = 64;

/// Relative tolerance for the soft-404 length-similarity branch (5%).
const BODY_LEN_TOLERANCE: f64 = 0.05;

/// Whether two normalized-body lengths are close enough to be the same
/// (substantial) error page: both at least [`MIN_SIMILAR_BODY_LEN`] and within
/// [`BODY_LEN_TOLERANCE`] of the larger.
fn bodies_similar(baseline: usize, observed: usize) -> bool {
    if baseline < MIN_SIMILAR_BODY_LEN || observed < MIN_SIMILAR_BODY_LEN {
        return false;
    }
    let larger = baseline.max(observed) as f64;
    let diff = (baseline as i64 - observed as i64).unsigned_abs() as f64;
    diff <= larger * BODY_LEN_TOLERANCE
}

/// "API-shaped content" = a JSON/XML content-type, or a body that parses as JSON.
fn is_api_shaped(content_type: Option<&str>, body: &str) -> bool {
    if let Some(content_type) = content_type {
        let lower = content_type.to_ascii_lowercase();
        if lower.contains("json") || lower.contains("xml") {
            return true;
        }
    }
    let trimmed = body.trim();
    !trimmed.is_empty() && serde_json::from_str::<serde_json::Value>(trimmed).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wordlist::StaticWordlistProvider;

    /// Build an `Observed` from a status and a body, computing the same
    /// fingerprint the live probe would.
    fn observed(status: u16, content_type: Option<&str>, body: &str) -> Observed {
        let normalized = normalize_body(body);
        Observed {
            status,
            body_hash: hash_str(&normalized),
            body_len: normalized.len(),
            api_shaped: is_api_shaped(content_type, body),
            content_type: content_type.map(str::to_string),
        }
    }

    /// A 200 soft-404 baseline: the server answers unknown paths with 200 + a
    /// not-found body.
    fn soft_404_baseline() -> Baseline {
        let o = observed(200, Some("text/html"), "<h1>Not Found</h1>");
        Baseline {
            status: o.status,
            body_hash: o.body_hash,
            body_len: o.body_len,
        }
    }

    // --- Task 5.1: the classifier over the representative responses ----------

    #[test]
    fn classifies_200_api_as_accessible() {
        let baseline = soft_404_baseline();
        let resp = observed(200, Some("application/json"), r#"{"users":[{"id":1}]}"#);
        assert_eq!(classify(&resp, Some(&baseline)), Classification::Accessible);
    }

    #[test]
    fn classifies_200_soft_404_as_absent() {
        let baseline = soft_404_baseline();
        // The same 200 + not-found body the baseline learned.
        let resp = observed(200, Some("text/html"), "<h1>Not Found</h1>");
        assert_eq!(classify(&resp, Some(&baseline)), Classification::Absent);
    }

    #[test]
    fn classifies_200_soft_404_absent_even_with_reformatted_body() {
        let baseline = soft_404_baseline();
        // Whitespace differences must not defeat the fingerprint.
        let resp = observed(200, Some("text/html"), "  <h1>Not   Found</h1>\n");
        assert_eq!(classify(&resp, Some(&baseline)), Classification::Absent);
    }

    #[test]
    fn classifies_401_as_protected() {
        let baseline = soft_404_baseline();
        let resp = observed(401, Some("application/json"), r#"{"error":"unauthorized"}"#);
        assert_eq!(classify(&resp, Some(&baseline)), Classification::Protected);
    }

    #[test]
    fn classifies_403_as_protected() {
        let baseline = soft_404_baseline();
        let resp = observed(403, Some("text/plain"), "forbidden");
        assert_eq!(classify(&resp, Some(&baseline)), Classification::Protected);
    }

    #[test]
    fn classifies_404_as_absent() {
        let baseline = soft_404_baseline();
        let resp = observed(404, Some("text/plain"), "nope");
        assert_eq!(classify(&resp, Some(&baseline)), Classification::Absent);
    }

    #[test]
    fn classifies_500_as_erroring() {
        let baseline = soft_404_baseline();
        let resp = observed(500, Some("text/plain"), "boom");
        assert_eq!(classify(&resp, Some(&baseline)), Classification::Erroring);
    }

    // --- The classifier with a hard-404 baseline (the common case) -----------

    #[test]
    fn hard_404_baseline_suppresses_matching_404s_only() {
        let base_obs = observed(404, Some("text/plain"), "Not Found");
        let baseline = Baseline {
            status: base_obs.status,
            body_hash: base_obs.body_hash,
            body_len: base_obs.body_len,
        };
        // A matching 404 is absent.
        let missing = observed(404, Some("text/plain"), "Not Found");
        assert_eq!(classify(&missing, Some(&baseline)), Classification::Absent);
        // A 200 is distinct from the 404 baseline → accessible.
        let hit = observed(200, Some("application/json"), r#"{"ok":true}"#);
        assert_eq!(classify(&hit, Some(&baseline)), Classification::Accessible);
        // A 401 is distinct → protected.
        let locked = observed(401, None, "");
        assert_eq!(
            classify(&locked, Some(&baseline)),
            Classification::Protected
        );
    }

    #[test]
    fn without_baseline_status_drives_classification() {
        assert_eq!(
            classify(&observed(200, Some("application/json"), "{}"), None),
            Classification::Accessible
        );
        assert_eq!(
            classify(&observed(404, None, "x"), None),
            Classification::Absent
        );
        assert_eq!(
            classify(&observed(503, None, "x"), None),
            Classification::Erroring
        );
    }

    // --- Finding construction & the canonical mapping ------------------------

    fn target() -> Target {
        Target::parse("https://example.com").unwrap()
    }

    #[test]
    fn absent_yields_no_finding() {
        let resp = observed(404, None, "Not Found");
        assert!(finding_for(&target(), RestDiscoveryScanner::ID, "/ghost", &resp, None).is_none());
    }

    #[test]
    fn accessible_benign_is_info_info() {
        let resp = observed(200, Some("application/json"), r#"{"status":"ok"}"#);
        let finding =
            finding_for(&target(), RestDiscoveryScanner::ID, "/health", &resp, None).unwrap();
        assert_eq!(finding.status, Status::Info);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.scanner_id, RestDiscoveryScanner::ID);
        assert!(finding.title.contains("/health"));
        let evidence = finding.evidence.unwrap();
        assert_eq!(evidence["status"], 200);
        assert_eq!(evidence["classification"], "accessible");
        assert_eq!(evidence["api_shaped"], true);
        assert_eq!(evidence["path"], "/health");
    }

    #[test]
    fn accessible_sensitive_is_vulnerable() {
        let resp = observed(200, Some("application/json"), r#"{"token":"abc"}"#);
        let finding =
            finding_for(&target(), RestDiscoveryScanner::ID, "/admin", &resp, None).unwrap();
        assert_eq!(finding.status, Status::Vulnerable);
        assert_eq!(finding.severity, Severity::Medium);
        assert!(finding.recommendations.is_some());
    }

    #[test]
    fn protected_is_safe_info_even_for_sensitive_path() {
        // A 401 in front of a sensitive path is the desired state, not a finding
        // of vulnerability.
        let resp = observed(401, Some("application/json"), r#"{"error":"unauthorized"}"#);
        let finding =
            finding_for(&target(), RestDiscoveryScanner::ID, "/admin", &resp, None).unwrap();
        assert_eq!(finding.status, Status::Safe);
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.title.contains("Protected"));
    }

    #[test]
    fn erroring_is_reported_low_confidence() {
        let resp = observed(500, None, "boom");
        let finding = finding_for(
            &target(),
            RestDiscoveryScanner::ID,
            "/api/users",
            &resp,
            None,
        )
        .unwrap();
        assert_eq!(finding.status, Status::Info);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.evidence.unwrap()["classification"], "erroring");
    }

    // --- Path normalization & helpers ----------------------------------------

    #[test]
    fn normalize_path_adds_single_leading_slash() {
        assert_eq!(normalize_path("health").as_deref(), Some("/health"));
        assert_eq!(normalize_path("/admin").as_deref(), Some("/admin"));
        assert_eq!(normalize_path("//double").as_deref(), Some("/double"));
        assert_eq!(normalize_path("  spaced  ").as_deref(), Some("/spaced"));
        assert_eq!(normalize_path("api/v1/").as_deref(), Some("/api/v1/"));
    }

    #[test]
    fn normalize_path_drops_blank_and_root() {
        assert_eq!(normalize_path(""), None);
        assert_eq!(normalize_path("   "), None);
        assert_eq!(normalize_path("/"), None);
        assert_eq!(normalize_path("///"), None);
    }

    #[test]
    fn candidate_url_is_origin_relative() {
        let base = Url::parse("https://example.com/app?x=1#frag").unwrap();
        let url = candidate_url(&base, "/api/users");
        assert_eq!(url.as_str(), "https://example.com/api/users");
    }

    #[test]
    fn is_api_shaped_detects_json_and_xml() {
        assert!(is_api_shaped(Some("application/json; charset=utf-8"), "{}"));
        assert!(is_api_shaped(Some("application/xml"), "<a/>"));
        // No content-type, but the body parses as JSON.
        assert!(is_api_shaped(None, r#"{"a":1}"#));
        // Plain HTML is not API-shaped.
        assert!(!is_api_shaped(Some("text/html"), "<html></html>"));
        assert!(!is_api_shaped(None, "just text"));
    }

    #[test]
    fn is_sensitive_flags_known_markers() {
        assert!(is_sensitive("/admin"));
        assert!(is_sensitive("/api/internal/metrics"));
        assert!(is_sensitive("/.env"));
        assert!(!is_sensitive("/health"));
        assert!(!is_sensitive("/api/users"));
    }

    #[test]
    fn bodies_similar_only_for_substantial_close_lengths() {
        // Short bodies never match on length alone — only an exact hash counts.
        assert!(!bodies_similar(18, 20));
        assert!(!bodies_similar(40, 41));
        // Substantial bodies within 5% match (a dynamic error page).
        assert!(bodies_similar(100, 104)); // 4% diff, both >= 64
        assert!(bodies_similar(2000, 2080)); // 4% diff
                                             // Substantial but far apart do not match.
        assert!(!bodies_similar(2000, 2400)); // 20% diff
    }

    // --- Task 2.2: candidate loading dedupes and normalizes ------------------

    #[tokio::test]
    async fn candidate_paths_unions_normalizes_and_dedupes() {
        let provider = StaticWordlistProvider::new()
            .with_list(
                ENDPOINT_LIST,
                vec!["health".into(), "/health".into(), "users".into()],
            )
            .with_list(
                API_BASES_LIST,
                vec!["/api/".into(), "users".into(), "/".into()],
            );
        let scanner = RestDiscoveryScanner::new(Arc::new(provider));
        let candidates = scanner.candidate_paths().await.unwrap();
        // "health" and "/health" collapse; "users" appears in both lists but once;
        // "/" is dropped; order is endpoints-first then bases.
        assert_eq!(candidates, vec!["/health", "/users", "/api/"]);
    }
}
