//! REST endpoint discovery — the foundational reconnaissance scanner.
//!
//! [`RestDiscoveryScanner`] probes a target's origin against a curated set of
//! candidate endpoint paths (the seeded `rest_api_bases` + `rest_endpoints`
//! lists) and reports which paths correspond to real endpoints, classifying each
//! as openly **accessible**, **protected** (auth required), or **erroring**.
//!
//! It owns none of the cross-cutting concerns: every request goes through
//! [`ScanContext::send`], so pacing, the rotating User-Agent, cancellation, and
//! progress all apply uniformly and the stealth floor cannot be bypassed. This is
//! the scanner template the remaining five (b01–b05) follow.
//!
//! ## Soft-404 handling
//!
//! Some targets answer unknown paths with `200 OK` and a generic "not found"
//! body (a *soft-404*). Before probing the wordlist the scanner sends one request
//! to a random, unlikely path and fingerprints the response (status + a
//! whitespace-normalized body hash + body length). A candidate whose response
//! matches that fingerprint is classified **absent** and never reported — so a
//! soft-404 site does not drown the operator in false findings.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::header::CONTENT_TYPE;
use url::Url;

use abyssum_core::{
    BaseScanner, Error, Finding, ProgressUpdate, ReferenceStore, RequestSpec, Result, ScanContext,
    ScannerFactory, ScannerRegistry, Severity, Status, Target,
};

/// The stable scanner id. The registry keys on this and a scan selects by it; it
/// must never change.
const ID: &str = "rest_discovery";

/// The seeded wordlists this scanner draws its candidate paths from. Bases are
/// path prefixes (e.g. `/api/v1/`); endpoints are bare names (e.g. `health`).
/// Both are normalized to leading-slash paths and merged into one candidate set.
const WORDLIST_API_BASES: &str = "rest_api_bases";
const WORDLIST_ENDPOINTS: &str = "rest_endpoints";

/// Maximum absolute body-length difference (bytes) at which a response counts as
/// the same not-found page as the soft-404 baseline. Catches reflected-path
/// variations of one templated error page.
const SOFT_404_LEN_TOLERANCE: usize = 64;

/// The length-similarity soft-404 signal only applies to sizeable bodies
/// (templated error pages, where reflected-path variation is the realistic
/// concern). Tiny bodies must match the baseline *exactly* via the normalized
/// hash — two short responses of similar length are not reliably "the same page".
const SOFT_404_MIN_BODY_FOR_LEN_MATCH: usize = 256;

/// Where a [`RestDiscoveryScanner`] draws its candidate paths.
enum CandidateSource {
    /// The seeded reference-data store: loaded once per scan run by list name.
    Store(ReferenceStore),
    /// A fixed in-memory list (constructed directly; primarily for tests and
    /// callers that supply their own candidates).
    Fixed(Vec<String>),
}

/// Discovers REST endpoints by probing a curated wordlist against a target.
pub struct RestDiscoveryScanner {
    source: CandidateSource,
}

impl RestDiscoveryScanner {
    /// The stable scanner id, exposed for registration and selection.
    pub const ID: &'static str = ID;

    /// Build a scanner that loads its wordlist from the seeded reference-data
    /// store (the production constructor; see [`register`]).
    pub fn new(store: ReferenceStore) -> Self {
        Self {
            source: CandidateSource::Store(store),
        }
    }

    /// Build a scanner over a fixed, in-memory candidate list. Entries are
    /// normalized (leading slash) and deduped just like the seeded lists.
    pub fn with_paths<I, S>(paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            source: CandidateSource::Fixed(paths.into_iter().map(Into::into).collect()),
        }
    }

    /// The deduped, leading-slash-normalized candidate paths for this scan run.
    ///
    /// For a store-backed scanner this loads `rest_api_bases` then `rest_endpoints`
    /// (each once) and merges them; a missing list contributes nothing rather than
    /// erroring. Exposed so a surface can preview what would be probed.
    pub async fn candidate_paths(&self) -> Result<Vec<String>> {
        let raw = match &self.source {
            CandidateSource::Fixed(paths) => paths.clone(),
            CandidateSource::Store(store) => {
                let mut raw = store.wordlist_values(WORDLIST_API_BASES).await?;
                raw.extend(store.wordlist_values(WORDLIST_ENDPOINTS).await?);
                raw
            }
        };
        Ok(normalize_candidates(raw))
    }
}

#[async_trait]
impl BaseScanner for RestDiscoveryScanner {
    fn id(&self) -> &str {
        ID
    }

    fn name(&self) -> &str {
        "REST Endpoint Discovery"
    }

    fn description(&self) -> &str {
        "Probes a target's origin against a curated endpoint wordlist to surface \
         undocumented or hidden REST API endpoints, classifying each discovered \
         endpoint as accessible, protected, or erroring."
    }

    async fn scan(&self, target: &Target, ctx: &ScanContext) -> Result<Vec<Finding>> {
        self.validate_target(target)?;

        let candidates = self.candidate_paths().await?;
        let total = candidates.len();
        let mut findings = Vec::new();
        if total == 0 {
            // No seeded wordlist (or an empty fixed list): nothing to probe, and
            // no request is issued.
            return Ok(findings);
        }

        // Establish the soft-404 baseline first (its request is this domain's free
        // first request — no pacing delay). A failure here just means we fall back
        // to status-only classification.
        let baseline = probe_baseline(target, ctx).await;

        for (index, path) in candidates.iter().enumerate() {
            // Stop promptly on cancellation, returning the findings gathered so
            // far rather than erroring.
            if ctx.is_cancelled() {
                break;
            }

            let url = match target.base_url().join(path) {
                Ok(url) => url,
                Err(_) => {
                    // An unparseable candidate is skipped, never fatal.
                    ctx.report_progress(progress(index + 1, total, path));
                    continue;
                }
            };

            match probe(ctx, url).await {
                Ok(response) => {
                    let classification = classify(&response, baseline.as_ref());
                    if let Some(finding) = finding_for(target, path, &response, classification) {
                        findings.push(finding);
                    }
                }
                Err(_) => {
                    // A transport failure or a pacing halt (sustained target
                    // distress). Respect it: stop probing this host and return what
                    // we have rather than hammering a struggling target.
                    break;
                }
            }

            ctx.report_progress(progress(index + 1, total, path));
        }

        Ok(findings)
    }
}

/// Register the REST discovery scanner under its stable id, baking in the seeded
/// store the factory cannot otherwise reach (the registry only hands factories a
/// `Config`). Each created instance shares the cheaply-cloneable store.
pub fn register(registry: &mut ScannerRegistry, store: &ReferenceStore) {
    let store = store.clone();
    let factory: ScannerFactory = Arc::new(move |_config| {
        Box::new(RestDiscoveryScanner::new(store.clone())) as Box<dyn BaseScanner>
    });
    registry.register(ID, factory);
}

/// Build a scanner-internal progress update for the candidate at `completed` of
/// `total`, naming the path currently being probed.
fn progress(completed: usize, total: usize, path: &str) -> ProgressUpdate {
    ProgressUpdate::new(ID, completed, total)
        .current_item(path.to_string())
        .message(format!("probing {completed}/{total}"))
}

/// Merge raw wordlist entries into deduped candidate paths, each carrying exactly
/// one leading slash. Order is preserved (first occurrence wins); blank entries
/// are dropped.
fn normalize_candidates<I, S>(raw: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for entry in raw {
        let trimmed = entry.as_ref().trim();
        if trimmed.is_empty() {
            continue;
        }
        let path = normalize_leading_slash(trimmed);
        if seen.insert(path.clone()) {
            out.push(path);
        }
    }
    out
}

/// Normalize a path to exactly one leading slash: `health` -> `/health`,
/// `//api` -> `/api`, `/api/` -> `/api/`, `/` -> `/`.
fn normalize_leading_slash(s: &str) -> String {
    format!("/{}", s.trim_start_matches('/'))
}

/// A probed response reduced to the fields classification needs.
#[derive(Debug, Clone)]
struct ProbeResponse {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

/// A fingerprint of the soft-404 baseline response.
#[derive(Debug, Clone)]
struct Baseline {
    status: u16,
    body_hash: u64,
    body_len: usize,
}

impl Baseline {
    fn from_response(response: &ProbeResponse) -> Self {
        Self {
            status: response.status,
            body_hash: normalized_body_hash(&response.body),
            body_len: response.body.len(),
        }
    }

    /// Whether `response` looks like the same not-found page as this baseline:
    /// the same status, and either an equal normalized-body hash or — for
    /// sizeable bodies — a body length within tolerance.
    fn matches(&self, response: &ProbeResponse) -> bool {
        if self.status != response.status {
            return false;
        }
        if normalized_body_hash(&response.body) == self.body_hash {
            return true;
        }
        if self.body_len >= SOFT_404_MIN_BODY_FOR_LEN_MATCH {
            return response.body.len().abs_diff(self.body_len) <= SOFT_404_LEN_TOLERANCE;
        }
        false
    }
}

/// How a probed path was classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Classification {
    /// 2xx, distinct from the not-found baseline — an openly reachable endpoint.
    Accessible,
    /// 401/403 — the endpoint exists but requires authentication/authorization.
    Protected,
    /// 5xx — the endpoint appears to exist but is erroring (low confidence).
    Erroring,
    /// Not found, soft-404, or otherwise uninteresting — not reported.
    Absent,
}

/// Hash of a response body after collapsing whitespace runs to single spaces and
/// trimming, so trivial formatting differences do not defeat the soft-404 match.
///
/// The digest uses [`std::collections::hash_map::DefaultHasher`], whose output is
/// **not** guaranteed stable across Rust versions or even recompilations. That is
/// safe here because a baseline and the candidate responses it is compared against
/// are always hashed within the same process during one scan run. This value MUST
/// NOT be persisted or cached and then compared against a hash produced by a later
/// run — it would silently fail to match. Reach for a stable digest (e.g. SHA-256)
/// before introducing any cross-run baseline fingerprint.
fn normalized_body_hash(body: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let text = String::from_utf8_lossy(body);
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    normalized.hash(&mut hasher);
    hasher.finish()
}

/// Whether a response carries API-shaped content: a JSON/XML content-type, or a
/// body that parses as JSON. A salient signal recorded in the finding evidence.
fn is_api_shaped(response: &ProbeResponse) -> bool {
    if let Some(content_type) = &response.content_type {
        let content_type = content_type.to_ascii_lowercase();
        if content_type.contains("json") || content_type.contains("xml") {
            return true;
        }
    }
    serde_json::from_slice::<serde_json::Value>(&response.body).is_ok()
}

/// Classify one probed response against the soft-404 baseline.
fn classify(response: &ProbeResponse, baseline: Option<&Baseline>) -> Classification {
    // Soft-404 first: a response matching the not-found baseline is absent even
    // when its status (e.g. 200) would otherwise read as present.
    if let Some(baseline) = baseline {
        if baseline.matches(response) {
            return Classification::Absent;
        }
    }
    match response.status {
        401 | 403 => Classification::Protected,
        status if (200..300).contains(&status) => Classification::Accessible,
        status if (500..600).contains(&status) => Classification::Erroring,
        _ => Classification::Absent,
    }
}

/// Build the [`Finding`] for a classified probe, or `None` when the path is
/// absent (and so not reported). Evidence carries the path, observed status, and
/// the salient response signals.
fn finding_for(
    target: &Target,
    path: &str,
    response: &ProbeResponse,
    classification: Classification,
) -> Option<Finding> {
    let (status, severity, title, description, label) = match classification {
        Classification::Accessible => (
            Status::Info,
            Severity::Info,
            format!("Discovered accessible endpoint {path}"),
            format!(
                "GET {path} returned HTTP {} with a response distinct from the not-found \
                 baseline; the endpoint is reachable.",
                response.status
            ),
            "accessible",
        ),
        Classification::Protected => (
            Status::Safe,
            Severity::Info,
            format!("Discovered protected endpoint {path}"),
            format!(
                "GET {path} returned HTTP {} (authentication or authorization required); \
                 the endpoint exists but is protected.",
                response.status
            ),
            "protected",
        ),
        Classification::Erroring => (
            Status::Info,
            Severity::Low,
            format!("Endpoint {path} returned a server error"),
            format!(
                "GET {path} returned HTTP {}; the endpoint appears to exist but is erroring \
                 (reported with low confidence).",
                response.status
            ),
            "erroring",
        ),
        Classification::Absent => return None,
    };

    let evidence = serde_json::json!({
        "path": path,
        "status": response.status,
        "content_type": response.content_type,
        "api_shaped": is_api_shaped(response),
        "body_length": response.body.len(),
        "classification": label,
    });

    Some(
        Finding::builder(ID, target.clone(), title)
            .status(status)
            .severity(severity)
            .description(description)
            .evidence(evidence)
            .build(),
    )
}

/// Probe one URL through the paced scan context and reduce the response to the
/// fields classification needs.
async fn probe(ctx: &ScanContext, url: Url) -> Result<ProbeResponse> {
    let response = ctx.send(RequestSpec::get(url)).await?;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let body = response
        .bytes()
        .await
        .map_err(|e| Error::Http(e.to_string()))?
        .to_vec();
    Ok(ProbeResponse {
        status,
        content_type,
        body,
    })
}

/// Send one request to a random, unlikely path to fingerprint the target's
/// not-found response. Returns `None` if the probe fails (we then fall back to
/// status-only classification).
async fn probe_baseline(target: &Target, ctx: &ScanContext) -> Option<Baseline> {
    let random = format!("/abyssum-probe-{}", uuid::Uuid::new_v4());
    let url = target.base_url().join(&random).ok()?;
    match probe(ctx, url).await {
        Ok(response) => Some(Baseline::from_response(&response)),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, content_type: Option<&str>, body: &str) -> ProbeResponse {
        ProbeResponse {
            status,
            content_type: content_type.map(|s| s.to_string()),
            body: body.as_bytes().to_vec(),
        }
    }

    fn target() -> Target {
        Target::parse("https://example.com").unwrap()
    }

    // --- Metadata (tasks 1.2) --------------------------------------------------

    #[test]
    fn metadata_is_stable() {
        let scanner = RestDiscoveryScanner::with_paths(["/x"]);
        assert_eq!(scanner.id(), "rest_discovery");
        assert_eq!(RestDiscoveryScanner::ID, "rest_discovery");
        assert!(!scanner.name().is_empty());
        assert!(!scanner.description().is_empty());
    }

    // --- Wordlist normalization + dedup (task 2.2) -----------------------------

    #[test]
    fn normalizes_leading_slashes_and_dedupes_preserving_order() {
        let raw = vec![
            "health",     // -> /health
            "/health",    // dup of /health
            "/api/v1/",   // kept as-is (trailing slash preserved)
            "users",      // -> /users
            "  spaced  ", // trimmed -> /spaced
            "//double",   // -> /double
            "",           // dropped
            "   ",        // dropped
        ];
        let got = normalize_candidates(raw);
        assert_eq!(
            got,
            vec![
                "/health".to_string(),
                "/api/v1/".to_string(),
                "/users".to_string(),
                "/spaced".to_string(),
                "/double".to_string(),
            ]
        );
    }

    #[test]
    fn normalize_leading_slash_handles_root_and_bare() {
        assert_eq!(normalize_leading_slash("/"), "/");
        assert_eq!(normalize_leading_slash("health"), "/health");
        assert_eq!(normalize_leading_slash("/api/"), "/api/");
        assert_eq!(normalize_leading_slash("///x"), "/x");
    }

    #[tokio::test]
    async fn fixed_source_candidate_paths_are_normalized() {
        let scanner = RestDiscoveryScanner::with_paths(["health", "/health", "users"]);
        let paths = scanner.candidate_paths().await.unwrap();
        assert_eq!(paths, vec!["/health".to_string(), "/users".to_string()]);
    }

    // --- Classifier matrix (task 5.1) ------------------------------------------

    #[test]
    fn classifies_200_api_as_accessible() {
        // Baseline is a 404 not-found, so the 200 response is plainly distinct.
        let baseline = Baseline::from_response(&resp(404, Some("text/plain"), "not found"));
        let api = resp(200, Some("application/json"), r#"{"ok":true}"#);
        assert_eq!(classify(&api, Some(&baseline)), Classification::Accessible);
    }

    #[test]
    fn classifies_200_soft_404_as_absent() {
        // The target answers unknown paths with 200 + a generic body. The baseline
        // captures it; an identical body on a probed path matches -> absent.
        let body = "<html><body>Page not found</body></html>";
        let baseline = Baseline::from_response(&resp(200, Some("text/html"), body));
        let soft = resp(200, Some("text/html"), body);
        assert_eq!(classify(&soft, Some(&baseline)), Classification::Absent);
    }

    #[test]
    fn classifies_401_and_403_as_protected() {
        let baseline = Baseline::from_response(&resp(404, None, "nope"));
        assert_eq!(
            classify(&resp(401, Some("application/json"), "{}"), Some(&baseline)),
            Classification::Protected
        );
        assert_eq!(
            classify(&resp(403, Some("application/json"), "{}"), Some(&baseline)),
            Classification::Protected
        );
    }

    #[test]
    fn classifies_404_as_absent() {
        let baseline = Baseline::from_response(&resp(404, None, "not found"));
        assert_eq!(
            classify(&resp(404, None, "not found"), Some(&baseline)),
            Classification::Absent
        );
        // Even with no baseline, a 404 is absent by status.
        assert_eq!(
            classify(&resp(404, None, "x"), None),
            Classification::Absent
        );
    }

    #[test]
    fn classifies_500_as_erroring() {
        let baseline = Baseline::from_response(&resp(404, None, "nope"));
        assert_eq!(
            classify(&resp(500, Some("text/html"), "boom"), Some(&baseline)),
            Classification::Erroring
        );
    }

    #[test]
    fn unmatched_other_4xx_is_absent() {
        assert_eq!(
            classify(&resp(400, None, "bad"), None),
            Classification::Absent
        );
        assert_eq!(
            classify(&resp(405, None, "no"), None),
            Classification::Absent
        );
    }

    // --- Soft-404 fingerprint matching -----------------------------------------

    #[test]
    fn baseline_matches_only_same_status() {
        let baseline = Baseline::from_response(&resp(200, None, "not found"));
        assert!(baseline.matches(&resp(200, None, "not found")));
        // Different status never matches, even with an identical body.
        assert!(!baseline.matches(&resp(404, None, "not found")));
    }

    #[test]
    fn baseline_length_tolerance_applies_only_to_large_bodies() {
        // Two sizeable templated pages differing only by a reflected path (within
        // tolerance) match; a much larger body does not.
        let big = "x".repeat(400);
        let baseline = Baseline::from_response(&resp(200, None, &big));
        let near = "x".repeat(400 - 20) + "/reflected/path"; // len within 64 of 400
        assert!(baseline.matches(&resp(200, None, &near)));
        let far = "x".repeat(800);
        assert!(!baseline.matches(&resp(200, None, &far)));

        // Tiny bodies of similar length must NOT match by length alone — only the
        // exact normalized hash counts, so a short distinct body stays distinct.
        let small_baseline = Baseline::from_response(&resp(200, None, "not found"));
        assert!(!small_baseline.matches(&resp(200, None, r#"{"ok":1}"#)));
    }

    #[test]
    fn normalized_hash_ignores_whitespace_only_differences() {
        let a = normalized_body_hash(b"hello   world\n\t");
        let b = normalized_body_hash(b"hello world");
        assert_eq!(a, b);
        assert_ne!(
            normalized_body_hash(b"hello world"),
            normalized_body_hash(b"goodbye world")
        );
    }

    // --- api-shaped detection --------------------------------------------------

    #[test]
    fn detects_api_shaped_content() {
        assert!(is_api_shaped(&resp(
            200,
            Some("application/json"),
            "not json"
        )));
        assert!(is_api_shaped(&resp(200, Some("application/xml"), "<a/>")));
        assert!(is_api_shaped(&resp(200, Some("text/plain"), r#"{"k":1}"#)));
        assert!(!is_api_shaped(&resp(
            200,
            Some("text/html"),
            "<html></html>"
        )));
        assert!(!is_api_shaped(&resp(200, None, "plain text")));
    }

    // --- Finding construction (task 4.3) ---------------------------------------

    #[test]
    fn accessible_finding_maps_to_info_info_with_evidence() {
        let response = resp(200, Some("application/json"), r#"{"users":[]}"#);
        let finding = finding_for(
            &target(),
            "/api/users",
            &response,
            Classification::Accessible,
        )
        .expect("accessible classification yields a finding");
        assert_eq!(finding.scanner_id, "rest_discovery");
        assert_eq!(finding.status, Status::Info);
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.title.contains("/api/users"));
        let evidence = finding.evidence.expect("evidence present");
        assert_eq!(evidence["path"], "/api/users");
        assert_eq!(evidence["status"], 200);
        assert_eq!(evidence["classification"], "accessible");
        assert_eq!(evidence["api_shaped"], true);
    }

    #[test]
    fn protected_finding_maps_to_safe_info() {
        let response = resp(401, Some("application/json"), r#"{"error":"unauthorized"}"#);
        let finding = finding_for(&target(), "/admin", &response, Classification::Protected)
            .expect("protected classification yields a finding");
        assert_eq!(finding.status, Status::Safe);
        assert_eq!(finding.severity, Severity::Info);
        assert!(finding.title.contains("/admin"));
        assert_eq!(finding.evidence.unwrap()["classification"], "protected");
    }

    #[test]
    fn erroring_finding_maps_to_info_low() {
        let response = resp(500, Some("text/html"), "boom");
        let finding = finding_for(&target(), "/broken", &response, Classification::Erroring)
            .expect("erroring classification yields a finding");
        assert_eq!(finding.status, Status::Info);
        assert_eq!(finding.severity, Severity::Low);
    }

    #[test]
    fn absent_yields_no_finding() {
        let response = resp(404, None, "not found");
        assert!(finding_for(&target(), "/missing", &response, Classification::Absent).is_none());
    }
}
