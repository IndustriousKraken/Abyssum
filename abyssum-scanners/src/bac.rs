//! Broken Access Control (BAC) scanner.
//!
//! [`BacScanner`] probes a target's origin against a curated wordlist of
//! administrative and sensitive paths (the seeded `bac_paths` list) *with any
//! authorization credential stripped*, and reports the paths that respond as if
//! the anonymous caller were authorized — an admin interface served without a
//! login, a sensitive endpoint dumping user records, credentials, or database
//! details. Broken access control is the most impactful and common API
//! vulnerability class, so a path reachable unauthenticated maps directly to a
//! reportable bug-bounty finding.
//!
//! Like every scanner it owns none of the cross-cutting concerns: every probe
//! goes through [`ScanContext::send`], so pacing, the rotating User-Agent,
//! cancellation, and progress all apply uniformly and the stealth floor cannot be
//! bypassed. The one BAC-specific twist is that each probe is issued with
//! [`RequestSpec::without_credential`], so a positive result reflects access
//! available *without* authentication even when the scan is otherwise configured
//! with a credential.
//!
//! ## What counts as broken access control
//!
//! Per unauthenticated response to a sensitive path:
//!
//! | Observed | Outcome |
//! |----------|---------|
//! | 2xx + recognized not-found / generic-error body, or the site's catch-all page | discarded (no finding) |
//! | 2xx + sensitive content (credentials, DB, PII, user data, multi-record JSON) | finding; severity scales with endpoint kind + data class |
//! | 2xx on a sensitive/admin-named path with no obvious data | finding (medium) — such a path must not be openly reachable |
//! | 3xx to another sensitive location | followed once; the target is flagged only if it is itself reachable unauthenticated with sensitive/admin content |
//! | 401 / 403 | properly protected — no finding |
//! | 404 / 5xx / other | absent or erroring — no finding |
//!
//! The error-page guard (recognized not-found phrasing, default server-error
//! pages, very short HTML bodies) plus a homepage catch-all fingerprint are the
//! false-positive suppressors; the observable contract is "a recognized
//! error/not-found page on a sensitive path is not reported as unauthorized
//! access".

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::header::{CONTENT_TYPE, LOCATION};
use url::Url;

use abyssum_core::{
    BaseScanner, Error, Finding, ProgressUpdate, ReferenceStore, RequestSpec, Result, ScanContext,
    ScannerFactory, ScannerRegistry, Severity, Status, Target,
};

/// The stable scanner id. The registry keys on this and a scan selects by it; it
/// must never change.
const ID: &str = "bac";

/// The seeded wordlist this scanner draws its candidate paths from: the full
/// admin/sensitive-path list (`add-seed-data` ships `bac_paths`, with
/// `bac_paths_short` reserved for a fast profile). A scanner loads it by name once
/// per scan run.
const WORDLIST_BAC_PATHS: &str = "bac_paths";

/// Upper bound on the response body buffered per probe. A probed endpoint is
/// untrusted and could stream an unbounded (or maliciously large) response, so the
/// scanner never reads a whole body into memory: bytes beyond this cap are dropped
/// and the response is flagged `truncated`. Classification keys first on the status
/// code, so a capped body never changes the *reachable-vs-protected* verdict — only
/// the body-derived content signals treat a truncated body conservatively.
const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

/// How many leading bytes of the response body to keep as the bounded evidence
/// sample (UTF-8 lossy). Enough to recognize the exposure, never the whole body.
const SAMPLE_BYTES: usize = 512;

/// A JSON collection (a top-level array, or the largest array field of a top-level
/// object) of at least this many records reads as a data dump — a sensitive-content
/// signal on its own.
const MIN_SENSITIVE_JSON_RECORDS: usize = 5;

/// An HTML body shorter than this is treated as an error/placeholder stub rather
/// than a real interface, and so is not reported as an exposure.
const MIN_HTML_BODY_BYTES: usize = 512;

/// This many or more e-mail addresses in one body reads as a PII dump.
const MANY_EMAILS_THRESHOLD: usize = 5;

/// Maximum absolute body-length difference (bytes) at which a response counts as
/// the same page as the homepage catch-all baseline.
const CATCHALL_LEN_TOLERANCE: usize = 64;

/// The catch-all length-similarity signal only applies to sizeable bodies; tiny
/// bodies must match the baseline *exactly* via the normalized hash.
const CATCHALL_MIN_BODY_FOR_LEN_MATCH: usize = 256;

/// Path fragments that mark an endpoint as *administrative* (the more sensitive
/// kind). Matched case-insensitively as substrings of the path.
const ADMIN_KEYWORDS: &[&str] = &[
    "admin",
    "backoffice",
    "manage",
    "internal",
    "control",
    "dashboard",
    "panel",
    "system",
    "debug",
    "logs",
];

/// Extra path fragments (beyond [`ADMIN_KEYWORDS`]) that mark a location as
/// *sensitive* — used to decide whether a redirect target is worth following.
const SENSITIVE_EXTRA_KEYWORDS: &[&str] = &[
    "settings", "account", "profile", "users", "user", "secure", "auth", "config", "private",
    "secret",
];

/// The class of data a sensitive-content signal exposes, ordered least to most
/// sensitive so the overall class of a response is the maximum over its signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DataClass {
    /// No obvious sensitive content.
    None,
    /// A user-record listing / multi-record data dump.
    UserData,
    /// Personally-identifiable information (SSNs, card numbers, many e-mails).
    Pii,
    /// Credentials or database/secret material.
    Credentials,
}

impl DataClass {
    /// A stable, lowercase label for finding evidence.
    fn label(self) -> &'static str {
        match self {
            DataClass::None => "none",
            DataClass::UserData => "user_data",
            DataClass::Pii => "pii",
            DataClass::Credentials => "credentials",
        }
    }
}

/// The sensitive-content keyword table: each `(needle, class, label)` flags `class`
/// when `needle` appears (case-insensitive) in the body, recording `label` as
/// evidence. The set is a tunable default — the observable contract is the data
/// class it yields, not the exact strings.
const SENSITIVE_KEYWORDS: &[(&str, DataClass, &str)] = &[
    ("db_password", DataClass::Credentials, "db_password"),
    ("password", DataClass::Credentials, "password"),
    ("passwd", DataClass::Credentials, "password"),
    ("secret_key", DataClass::Credentials, "secret_key"),
    ("client_secret", DataClass::Credentials, "client_secret"),
    ("secret", DataClass::Credentials, "secret"),
    ("api_key", DataClass::Credentials, "api_key"),
    ("apikey", DataClass::Credentials, "api_key"),
    ("access_key", DataClass::Credentials, "access_key"),
    ("private_key", DataClass::Credentials, "private_key"),
    (
        "begin rsa private key",
        DataClass::Credentials,
        "private_key_block",
    ),
    ("authorization", DataClass::Credentials, "authorization"),
    ("ssn", DataClass::Pii, "ssn"),
    ("social_security", DataClass::Pii, "ssn"),
    ("credit_card", DataClass::Pii, "credit_card"),
    ("creditcard", DataClass::Pii, "credit_card"),
    ("card_number", DataClass::Pii, "card_number"),
];

/// Whether an administrative or merely sensitive endpoint was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointKind {
    /// An administrative endpoint (an admin-named path).
    Admin,
    /// A sensitive — but not specifically administrative — endpoint.
    Sensitive,
}

impl EndpointKind {
    fn label(self) -> &'static str {
        match self {
            EndpointKind::Admin => "admin",
            EndpointKind::Sensitive => "sensitive",
        }
    }
}

/// What an exposed (reachable-unauthenticated) response revealed: the endpoint
/// kind, the class of data exposed, and the human-facing signal labels observed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Exposure {
    kind: EndpointKind,
    data: DataClass,
    signals: Vec<String>,
}

/// The verdict for one unauthenticated response to a sensitive path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Reachable unauthenticated — a broken-access-control finding.
    Exposed(Exposure),
    /// A 3xx to another sensitive location worth one follow-up probe.
    FollowRedirect { location: String },
    /// Properly protected (401/403) — not a finding.
    Protected,
    /// Absent / erroring / soft-not-found / catch-all — not a finding.
    NotExposed,
}

/// Where a [`BacScanner`] draws its candidate paths.
enum CandidateSource {
    /// The seeded reference-data store: loaded once per scan run by list name.
    Store(ReferenceStore),
    /// A fixed in-memory list (constructed directly; primarily for tests).
    Fixed(Vec<String>),
}

/// Detects broken access control by probing sensitive paths unauthenticated.
pub struct BacScanner {
    source: CandidateSource,
}

impl BacScanner {
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
    /// normalized (one leading slash) and deduped just like the seeded list.
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
    /// For a store-backed scanner this loads `bac_paths` once; a missing list
    /// contributes nothing rather than erroring. Exposed so a surface can preview
    /// what would be probed.
    pub async fn candidate_paths(&self) -> Result<Vec<String>> {
        let raw = match &self.source {
            CandidateSource::Fixed(paths) => paths.clone(),
            CandidateSource::Store(store) => store.wordlist_values(WORDLIST_BAC_PATHS).await?,
        };
        Ok(normalize_candidates(raw))
    }
}

#[async_trait]
impl BaseScanner for BacScanner {
    fn id(&self) -> &str {
        ID
    }

    fn name(&self) -> &str {
        "Broken Access Control"
    }

    fn description(&self) -> &str {
        "Probes a curated wordlist of administrative and sensitive paths with any \
         authorization credential stripped, reporting endpoints reachable without \
         authentication — an admin interface served anonymously, or a sensitive \
         endpoint exposing credentials, database details, PII, or user records."
    }

    async fn scan(&self, target: &Target, ctx: &ScanContext) -> Result<Vec<Finding>> {
        self.validate_target(target)?;

        let candidates = self.candidate_paths().await?;
        let total = candidates.len();
        let mut findings = Vec::new();
        if total == 0 {
            // No seeded wordlist (or an empty fixed list): nothing to probe, and no
            // request is issued.
            return Ok(findings);
        }

        // Establish a baseline reachability probe of the base URL first (its request
        // is this domain's free first request — no pacing delay). Beyond confirming
        // reachability it fingerprints the homepage, so a catch-all site that serves
        // the same page for every route does not yield phantom findings.
        let baseline = probe_baseline(target, ctx).await;

        for (index, path) in candidates.iter().enumerate() {
            // Stop promptly on cancellation, returning the findings gathered so far
            // rather than erroring.
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

            match probe(ctx, url.clone()).await {
                Ok(response) => match evaluate(path, &response, baseline.as_ref()) {
                    Verdict::Exposed(exposure) => {
                        findings.push(build_finding(
                            target, path, &url, &response, &exposure, None,
                        ));
                    }
                    Verdict::FollowRedirect { location } => {
                        if let Some(finding) = self
                            .follow_redirect(target, ctx, &url, path, &location, baseline.as_ref())
                            .await?
                        {
                            findings.push(finding);
                        }
                    }
                    Verdict::Protected | Verdict::NotExposed => {}
                },
                // Cancellation is not a transport failure: surface it rather than
                // masking it as a partial success.
                Err(Error::Cancelled) => return Err(Error::Cancelled),
                Err(err) => {
                    // A transport failure or a pacing halt (sustained target
                    // distress). Respect it: stop probing this host and return the
                    // findings gathered so far rather than hammering a struggling
                    // target — but log the halt so it is not silent.
                    tracing::warn!(
                        scanner = ID,
                        path = %path,
                        error = %err,
                        "stopping BAC scan after a request failure; returning partial findings"
                    );
                    break;
                }
            }

            ctx.report_progress(progress(index + 1, total, path));
        }

        Ok(findings)
    }
}

impl BacScanner {
    /// Follow a redirect from `from_path` to `location` exactly once and, if the
    /// target is itself reachable unauthenticated with sensitive/admin content,
    /// build the finding for it. A target that requires auth, is absent, or errors
    /// is not a vulnerability. Returns `Err(Error::Cancelled)` if cancelled while
    /// following.
    async fn follow_redirect(
        &self,
        target: &Target,
        ctx: &ScanContext,
        from_url: &Url,
        from_path: &str,
        location: &str,
        baseline: Option<&Baseline>,
    ) -> Result<Option<Finding>> {
        if ctx.is_cancelled() {
            return Ok(None);
        }
        // Resolve the redirect target and keep it on the same host: the operator
        // asked to scan this origin, not whatever a redirect points elsewhere at.
        let redirect_url = match resolve_same_host_redirect(from_url, location, target.host()) {
            Some(url) => url,
            None => return Ok(None),
        };

        match probe(ctx, redirect_url.clone()).await {
            Ok(response) => {
                let target_path = redirect_url.path().to_string();
                if let Verdict::Exposed(exposure) = evaluate(&target_path, &response, baseline) {
                    return Ok(Some(build_finding(
                        target,
                        &target_path,
                        &redirect_url,
                        &response,
                        &exposure,
                        Some(from_path),
                    )));
                }
                Ok(None)
            }
            Err(Error::Cancelled) => Err(Error::Cancelled),
            Err(err) => {
                tracing::warn!(
                    scanner = ID,
                    from = %from_path,
                    location = %location,
                    error = %err,
                    "redirect follow-up probe failed; treating the redirect target as not exposed"
                );
                Ok(None)
            }
        }
    }
}

/// Register the BAC scanner under its stable id, baking in the seeded store the
/// factory cannot otherwise reach (the registry only hands factories a `Config`).
/// Each created instance shares the cheaply-cloneable store.
pub fn register(registry: &mut ScannerRegistry, store: &ReferenceStore) {
    let store = store.clone();
    let factory: ScannerFactory =
        Arc::new(move |_config| Box::new(BacScanner::new(store.clone())) as Box<dyn BaseScanner>);
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
/// one leading slash. Order is preserved (first occurrence wins); blank entries are
/// dropped.
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

/// Normalize a path to exactly one leading slash: `admin` -> `/admin`,
/// `//admin` -> `/admin`, `/admin/` -> `/admin/`, `/` -> `/`.
fn normalize_leading_slash(s: &str) -> String {
    format!("/{}", s.trim_start_matches('/'))
}

/// A probed response reduced to the fields evaluation needs.
#[derive(Debug, Clone)]
struct ProbeResponse {
    status: u16,
    content_type: Option<String>,
    /// The `Location` header (present on redirects).
    location: Option<String>,
    body: Vec<u8>,
    /// Whether the body was capped at [`MAX_BODY_BYTES`].
    truncated: bool,
}

/// A fingerprint of the homepage baseline response, used to discard a catch-all
/// page served identically for every route.
#[derive(Debug, Clone)]
struct Baseline {
    status: u16,
    body_hash: u64,
    body_len: usize,
    truncated: bool,
}

impl Baseline {
    fn from_response(response: &ProbeResponse) -> Self {
        Self {
            status: response.status,
            body_hash: normalized_body_hash(&response.body),
            body_len: response.body.len(),
            truncated: response.truncated,
        }
    }

    /// Whether `response` looks like the same catch-all page as this baseline: the
    /// same status, and either an equal normalized-body hash or — for sizeable
    /// bodies — a body length within tolerance.
    fn matches(&self, response: &ProbeResponse) -> bool {
        if self.status != response.status {
            return false;
        }
        if normalized_body_hash(&response.body) == self.body_hash {
            return true;
        }
        // Length similarity is unsafe once a body was capped: two distinct oversized
        // pages both truncated to the cap share a length but are not the same page.
        if self.truncated || response.truncated {
            return false;
        }
        if self.body_len >= CATCHALL_MIN_BODY_FOR_LEN_MATCH {
            return response.body.len().abs_diff(self.body_len) <= CATCHALL_LEN_TOLERANCE;
        }
        false
    }
}

/// Hash of a response body after collapsing whitespace runs to single spaces and
/// trimming, so trivial formatting differences do not defeat the catch-all match.
///
/// The digest uses [`std::collections::hash_map::DefaultHasher`], whose output is
/// not stable across Rust versions. That is safe here because the baseline and the
/// candidates it is compared against are always hashed within one scan run; this
/// value MUST NOT be persisted and compared across runs.
fn normalized_body_hash(body: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let text = String::from_utf8_lossy(body);
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    normalized.hash(&mut hasher);
    hasher.finish()
}

/// Whether the endpoint at `path` is administrative or merely sensitive.
fn endpoint_kind(path: &str) -> EndpointKind {
    let lower = path.to_ascii_lowercase();
    if ADMIN_KEYWORDS.iter().any(|kw| lower.contains(kw)) {
        EndpointKind::Admin
    } else {
        EndpointKind::Sensitive
    }
}

/// Whether a redirect `location` points at a sensitive area worth following.
fn is_sensitive_location(location: &str) -> bool {
    let lower = location.to_ascii_lowercase();
    ADMIN_KEYWORDS
        .iter()
        .chain(SENSITIVE_EXTRA_KEYWORDS.iter())
        .any(|kw| lower.contains(kw))
}

/// Resolve a `Location` against the request URL and keep it only if it stays on the
/// same host (origin) as the scan target. A relative `Location` resolves against
/// `from_url`; an absolute one to a different host is dropped.
fn resolve_same_host_redirect(from_url: &Url, location: &str, host: Option<&str>) -> Option<Url> {
    let resolved = from_url.join(location).ok()?;
    match (resolved.host_str(), host) {
        (Some(resolved_host), Some(target_host)) if resolved_host == target_host => Some(resolved),
        // No target host to compare against: fall back to the request URL's host.
        (Some(resolved_host), None) => {
            if Some(resolved_host) == from_url.host_str() {
                Some(resolved)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Evaluate one unauthenticated response to the sensitive path `path` into a
/// verdict. Pure over its inputs, so the whole decision matrix is unit-testable
/// without a network.
fn evaluate(path: &str, response: &ProbeResponse, baseline: Option<&Baseline>) -> Verdict {
    let status = response.status;

    // 3xx: a redirect to another sensitive location is worth following once; any
    // other redirect target is not, on its own, a finding.
    if (300..400).contains(&status) {
        if let Some(location) = &response.location {
            if is_sensitive_location(location) {
                return Verdict::FollowRedirect {
                    location: location.clone(),
                };
            }
        }
        return Verdict::NotExposed;
    }

    // Authentication/authorization required: properly protected.
    if status == 401 || status == 403 {
        return Verdict::Protected;
    }

    // Success: decide exposed-vs-not. Anything else (404, 5xx, other 4xx) is absent
    // or erroring and never a finding.
    if (200..300).contains(&status) {
        // A page served identically to the homepage is a catch-all, not the real
        // sensitive endpoint.
        if let Some(baseline) = baseline {
            if baseline.matches(response) {
                return Verdict::NotExposed;
            }
        }
        let (data, signals) = detect_sensitive_content(response);
        // A body that clearly leaks sensitive content — or is a recognizable admin
        // interface — is exposed regardless of length. Only when no such strong
        // signal is present does the error/not-found guard get to suppress a
        // soft-404 or a short placeholder stub.
        let has_strong_signal =
            data != DataClass::None || signals.iter().any(|s| s == "admin_interface_marker");
        if !has_strong_signal && looks_like_error_page(response) {
            return Verdict::NotExposed;
        }
        return Verdict::Exposed(Exposure {
            kind: endpoint_kind(path),
            data,
            signals,
        });
    }

    Verdict::NotExposed
}

/// Whether a 2xx body is a recognized not-found / generic-error page (or a too-short
/// HTML stub) that should be discarded rather than reported as an exposure.
fn looks_like_error_page(response: &ProbeResponse) -> bool {
    // Recognized not-found / error phrasing is characteristic of short stub pages;
    // gating on a modest length avoids suppressing a large real interface that
    // merely mentions one of these phrases somewhere.
    const NOT_FOUND_PHRASES: &[&str] = &[
        "not found",
        "page not found",
        "404 not found",
        "no longer exists",
        "does not exist",
        "cannot be found",
        "nothing here",
        "resource not found",
    ];
    const ERROR_PHRASES: &[&str] = &[
        "internal server error",
        "500 internal",
        "service unavailable",
        "bad gateway",
        "an error occurred",
        "something went wrong",
    ];
    const ERROR_PAGE_MAX_BYTES: usize = 4096;

    if !response.truncated && response.body.len() <= ERROR_PAGE_MAX_BYTES {
        let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
        if NOT_FOUND_PHRASES
            .iter()
            .chain(ERROR_PHRASES.iter())
            .any(|p| lower.contains(p))
        {
            return true;
        }
    }

    // A very short HTML body is a placeholder/error stub, not a real interface.
    if is_html(response.content_type.as_deref())
        && !response.truncated
        && response.body.len() < MIN_HTML_BODY_BYTES
    {
        return true;
    }

    false
}

/// Detect the sensitive-content signals in a 2xx body, returning the overall data
/// class (the maximum over the signals seen) and the human-facing signal labels.
fn detect_sensitive_content(response: &ProbeResponse) -> (DataClass, Vec<String>) {
    let mut class = DataClass::None;
    let mut signals: Vec<String> = Vec::new();
    let push = |label: &str, signals: &mut Vec<String>| {
        if !signals.iter().any(|s| s == label) {
            signals.push(label.to_string());
        }
    };

    let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();

    for (needle, needle_class, label) in SENSITIVE_KEYWORDS {
        if lower.contains(needle) {
            class = class.max(*needle_class);
            push(label, &mut signals);
        }
    }

    // A dump of many e-mail addresses is a PII signal.
    if count_emails(&lower) >= MANY_EMAILS_THRESHOLD {
        class = class.max(DataClass::Pii);
        push("many_email_addresses", &mut signals);
    }

    // A JSON collection of many records is a data-dump signal.
    if is_json(response.content_type.as_deref()) && !response.truncated {
        if let Some(count) = json_collection_len(&response.body) {
            if count >= MIN_SENSITIVE_JSON_RECORDS {
                class = class.max(DataClass::UserData);
                push("multi_record_json", &mut signals);
            }
        }
    }

    // An admin-interface marker confirms a real admin UI was served (it does not, on
    // its own, raise the data class above the medium "reachable admin" floor).
    if lower.contains("admin panel")
        || lower.contains("admin dashboard")
        || lower.contains("control panel")
        || lower.contains("<title>admin")
    {
        push("admin_interface_marker", &mut signals);
    }

    (class, signals)
}

/// Count e-mail-address-like tokens in `text` (already lowercased). A token counts
/// when it has a non-empty local part, an `@`, and a domain bearing an interior dot.
fn count_emails(text: &str) -> usize {
    text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                ',' | ';' | '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ':' | '\\'
            )
    })
    .filter(|token| is_email_like(token))
    .count()
}

/// Whether `token` looks like an e-mail address.
fn is_email_like(token: &str) -> bool {
    let at = match token.find('@') {
        Some(i) => i,
        None => return false,
    };
    let (local, domain) = token.split_at(at);
    let domain = &domain[1..]; // drop the '@'
    if local.is_empty() || domain.len() < 3 {
        return false;
    }
    // The local part must be plausible (no second '@'), and the domain must carry an
    // interior dot (a.b) — not leading or trailing.
    if domain.contains('@') {
        return false;
    }
    match domain.find('.') {
        Some(dot) => dot > 0 && dot < domain.len() - 1,
        None => false,
    }
}

/// Whether a content-type names JSON.
fn is_json(content_type: Option<&str>) -> bool {
    content_type
        .map(|ct| ct.to_ascii_lowercase().contains("json"))
        .unwrap_or(false)
}

/// Whether a content-type names HTML.
fn is_html(content_type: Option<&str>) -> bool {
    content_type
        .map(|ct| ct.to_ascii_lowercase().contains("html"))
        .unwrap_or(false)
}

/// The record count of a JSON collection body: a top-level array's length, or the
/// length of the largest array field of a top-level object. `None` if the body is
/// not JSON or carries no array.
fn json_collection_len(body: &[u8]) -> Option<usize> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    match value {
        serde_json::Value::Array(items) => Some(items.len()),
        serde_json::Value::Object(map) => map
            .values()
            .filter_map(|v| v.as_array())
            .map(|a| a.len())
            .max(),
        _ => None,
    }
}

/// The severity of an exposure: credentials/database exposure is always critical;
/// sensitive data (PII / user records) on an admin endpoint is critical too, while
/// on a merely sensitive endpoint it is high; a reachable endpoint with no obvious
/// data is medium.
fn severity_of(kind: EndpointKind, data: DataClass) -> Severity {
    match data {
        DataClass::Credentials => Severity::Critical,
        DataClass::Pii | DataClass::UserData => match kind {
            EndpointKind::Admin => Severity::Critical,
            EndpointKind::Sensitive => Severity::High,
        },
        DataClass::None => Severity::Medium,
    }
}

/// Keep at most [`SAMPLE_BYTES`] leading bytes of `body` as a UTF-8 lossy evidence
/// sample, never the whole (possibly large) body.
fn bounded_sample(body: &[u8]) -> String {
    let end = body.len().min(SAMPLE_BYTES);
    String::from_utf8_lossy(&body[..end]).to_string()
}

/// Build the [`Finding`] for an exposed endpoint, carrying reproduction evidence:
/// the endpoint, observed status, endpoint kind, exposed-data class, the exposure
/// signals, and a bounded response sample. `redirected_from` is set when the
/// endpoint was reached by following a redirect.
fn build_finding(
    target: &Target,
    endpoint: &str,
    url: &Url,
    response: &ProbeResponse,
    exposure: &Exposure,
    redirected_from: Option<&str>,
) -> Finding {
    let severity = severity_of(exposure.kind, exposure.data);
    let kind_word = match exposure.kind {
        EndpointKind::Admin => "administrative",
        EndpointKind::Sensitive => "sensitive",
    };

    let title = match redirected_from {
        Some(from) => format!(
            "Broken access control: {endpoint} reachable unauthenticated via redirect from {from}"
        ),
        None => format!("Broken access control: {endpoint} reachable without authentication"),
    };

    let data_clause = match exposure.data {
        DataClass::Credentials => " and exposes credentials or database details",
        DataClass::Pii => " and exposes personally-identifiable information",
        DataClass::UserData => " and exposes a multi-record data set",
        DataClass::None => "",
    };
    let description = format!(
        "GET {} (issued without any authorization credential) returned HTTP {}; the {kind_word} \
         endpoint is reachable by an anonymous caller{data_clause}. Broken access control lets an \
         unauthenticated attacker reach a route that should require authentication or an elevated \
         role.",
        url.as_str(),
        response.status,
    );

    let mut evidence = serde_json::json!({
        "endpoint": endpoint,
        "url": url.as_str(),
        "status": response.status,
        "endpoint_kind": exposure.kind.label(),
        "data_class": exposure.data.label(),
        "exposure_signals": exposure.signals,
        "response_sample": bounded_sample(&response.body),
        "body_length": response.body.len(),
        "body_truncated": response.truncated,
    });
    if let Some(from) = redirected_from {
        evidence["redirected_from"] = serde_json::json!(from);
    }

    Finding::builder(ID, target.clone(), title)
        .status(Status::Vulnerable)
        .severity(severity)
        .description(description)
        .evidence(evidence)
        .recommendations(
            "Require authentication and authorization on this endpoint: administrative and \
             sensitive routes must reject unauthenticated requests (401/403) and never serve \
             sensitive data to anonymous callers. Verify the access-control check is enforced \
             server-side, not merely hidden in the UI.",
        )
        .build()
}

/// Probe one URL through the paced scan context **without** any credential, and
/// reduce the response to the fields evaluation needs.
///
/// The body is streamed through a bounded reader that buffers at most
/// [`MAX_BODY_BYTES`]: a probed endpoint is untrusted and could return an unbounded
/// (or maliciously large) body, so an oversized body is capped and flagged
/// (`truncated`) rather than read whole into memory.
async fn probe(ctx: &ScanContext, url: Url) -> Result<ProbeResponse> {
    let mut response = ctx.send(RequestSpec::get(url).without_credential()).await?;
    let status = response.status().as_u16();
    let content_type = header_str(&response, CONTENT_TYPE);
    let location = header_str(&response, LOCATION);

    let mut body = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| Error::Http(e.to_string()))?
    {
        let remaining = MAX_BODY_BYTES.saturating_sub(body.len());
        if chunk.len() > remaining {
            body.extend_from_slice(&chunk[..remaining]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }

    Ok(ProbeResponse {
        status,
        content_type,
        location,
        body,
        truncated,
    })
}

/// Read a response header as an owned string, if present and valid UTF-8.
fn header_str(response: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

/// Send the baseline reachability probe to the target's base URL (credential
/// stripped, like every BAC probe). Returns `None` if it fails — the scan then runs
/// without the catch-all guard rather than aborting.
async fn probe_baseline(target: &Target, ctx: &ScanContext) -> Option<Baseline> {
    match probe(ctx, target.base_url().clone()).await {
        Ok(response) => Some(Baseline::from_response(&response)),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::parse("https://example.com").unwrap()
    }

    fn resp(status: u16, content_type: Option<&str>, body: &str) -> ProbeResponse {
        ProbeResponse {
            status,
            content_type: content_type.map(|s| s.to_string()),
            location: None,
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    fn redirect(status: u16, location: &str) -> ProbeResponse {
        ProbeResponse {
            status,
            content_type: None,
            location: Some(location.to_string()),
            body: Vec::new(),
            truncated: false,
        }
    }

    // --- Metadata (tasks 1.1, 1.2) ---------------------------------------------

    #[test]
    fn metadata_is_stable() {
        let scanner = BacScanner::with_paths(["/admin"]);
        assert_eq!(scanner.id(), "bac");
        assert_eq!(BacScanner::ID, "bac");
        assert!(!scanner.name().is_empty());
        assert!(!scanner.description().is_empty());
    }

    // --- Wordlist normalization + dedup (task 2.2) -----------------------------

    #[test]
    fn normalizes_leading_slashes_and_dedupes_preserving_order() {
        let raw = vec![
            "admin",
            "/admin",
            "/api/admin",
            "manage",
            "  /logs  ",
            "//internal",
            "",
            "   ",
        ];
        let got = normalize_candidates(raw);
        assert_eq!(
            got,
            vec![
                "/admin".to_string(),
                "/api/admin".to_string(),
                "/manage".to_string(),
                "/logs".to_string(),
                "/internal".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn fixed_source_candidate_paths_are_normalized() {
        let scanner = BacScanner::with_paths(["admin", "/admin", "manage"]);
        let paths = scanner.candidate_paths().await.unwrap();
        assert_eq!(paths, vec!["/admin".to_string(), "/manage".to_string()]);
    }

    // --- Endpoint-kind classification ------------------------------------------

    #[test]
    fn admin_paths_are_admin_kind_others_sensitive() {
        assert_eq!(endpoint_kind("/admin"), EndpointKind::Admin);
        assert_eq!(endpoint_kind("/backoffice/logs"), EndpointKind::Admin);
        assert_eq!(endpoint_kind("/dashboard"), EndpointKind::Admin);
        assert_eq!(endpoint_kind("/api/users"), EndpointKind::Sensitive);
        assert_eq!(endpoint_kind("/api/profile"), EndpointKind::Sensitive);
    }

    // --- Evaluator matrix (task 7.1) -------------------------------------------

    #[test]
    fn exposed_admin_with_credentials_is_critical() {
        let body = r#"{"db_password":"hunter2","users":[]}"#;
        let verdict = evaluate("/admin", &resp(200, Some("application/json"), body), None);
        let exposure = match verdict {
            Verdict::Exposed(e) => e,
            other => panic!("expected exposed, got {other:?}"),
        };
        assert_eq!(exposure.kind, EndpointKind::Admin);
        assert_eq!(exposure.data, DataClass::Credentials);
        assert!(exposure.signals.iter().any(|s| s == "db_password"));
        assert_eq!(
            severity_of(exposure.kind, exposure.data),
            Severity::Critical
        );
    }

    #[test]
    fn soft_not_found_on_2xx_is_not_exposed() {
        // A sensitive path that answers 200 with a not-found stub is a soft-404.
        let verdict = evaluate(
            "/admin",
            &resp(
                200,
                Some("text/html"),
                "<html><body>404 Not Found</body></html>",
            ),
            None,
        );
        assert_eq!(verdict, Verdict::NotExposed);
    }

    #[test]
    fn benign_200_on_admin_is_exposed_medium() {
        // A 200 on an admin path with a benign, non-error body is still a finding —
        // an admin route must not be openly reachable — but only at medium.
        let verdict = evaluate("/admin", &resp(200, Some("application/json"), "{}"), None);
        let exposure = match verdict {
            Verdict::Exposed(e) => e,
            other => panic!("expected exposed, got {other:?}"),
        };
        assert_eq!(exposure.data, DataClass::None);
        assert_eq!(severity_of(exposure.kind, exposure.data), Severity::Medium);
    }

    #[test]
    fn protected_401_and_403_are_not_findings() {
        assert_eq!(
            evaluate("/admin", &resp(401, Some("application/json"), "{}"), None),
            Verdict::Protected
        );
        assert_eq!(
            evaluate("/admin", &resp(403, Some("application/json"), "{}"), None),
            Verdict::Protected
        );
    }

    #[test]
    fn absent_404_and_erroring_5xx_are_not_findings() {
        assert_eq!(
            evaluate("/admin", &resp(404, None, "not found"), None),
            Verdict::NotExposed
        );
        assert_eq!(
            evaluate("/admin", &resp(500, None, "boom"), None),
            Verdict::NotExposed
        );
        // An unrelated 4xx is also not a finding.
        assert_eq!(
            evaluate("/admin", &resp(405, None, "no"), None),
            Verdict::NotExposed
        );
    }

    #[test]
    fn redirect_to_sensitive_location_is_followed_elsewhere_is_not() {
        assert_eq!(
            evaluate("/dashboard", &redirect(302, "/admin/secret"), None),
            Verdict::FollowRedirect {
                location: "/admin/secret".to_string()
            }
        );
        // A redirect to a non-sensitive location (a login/marketing page) is not.
        assert_eq!(
            evaluate("/dashboard", &redirect(302, "/home"), None),
            Verdict::NotExposed
        );
    }

    // --- Sensitive-content + severity classes (tasks 4.2, 4.5) -----------------

    #[test]
    fn pii_on_sensitive_endpoint_is_high_on_admin_is_critical() {
        let body = r#"{"ssn":"123-45-6789","credit_card":"4111111111111111"}"#;
        let (class, _signals) =
            detect_sensitive_content(&resp(200, Some("application/json"), body));
        assert_eq!(class, DataClass::Pii);
        assert_eq!(severity_of(EndpointKind::Sensitive, class), Severity::High);
        assert_eq!(severity_of(EndpointKind::Admin, class), Severity::Critical);
    }

    #[test]
    fn multi_record_json_is_user_data_high_on_sensitive() {
        let body = r#"[{"id":1},{"id":2},{"id":3},{"id":4},{"id":5}]"#;
        let (class, signals) = detect_sensitive_content(&resp(200, Some("application/json"), body));
        assert_eq!(class, DataClass::UserData);
        assert!(signals.iter().any(|s| s == "multi_record_json"));
        assert_eq!(severity_of(EndpointKind::Sensitive, class), Severity::High);
    }

    #[test]
    fn few_json_records_are_not_a_data_dump() {
        let body = r#"[{"id":1},{"id":2}]"#;
        let (class, _signals) =
            detect_sensitive_content(&resp(200, Some("application/json"), body));
        assert_eq!(class, DataClass::None);
    }

    #[test]
    fn many_emails_are_pii() {
        let body = "a@x.com b@y.com c@z.com d@w.com e@v.com f@u.com";
        let (class, signals) = detect_sensitive_content(&resp(200, Some("text/plain"), body));
        assert_eq!(class, DataClass::Pii);
        assert!(signals.iter().any(|s| s == "many_email_addresses"));
    }

    #[test]
    fn email_counter_is_conservative() {
        assert_eq!(count_emails("just text, no addresses here"), 0);
        assert_eq!(count_emails("user@example.com"), 1);
        assert_eq!(count_emails("\"alice@a.io\",\"bob@b.io\""), 2);
        // '@mention' style and bare '@' are not e-mails.
        assert_eq!(count_emails("@handle plain@ a@b"), 0);
    }

    // --- Error-page guard (task 4.1) -------------------------------------------

    #[test]
    fn error_page_guard_discards_not_found_and_short_html() {
        assert!(looks_like_error_page(&resp(
            200,
            Some("text/html"),
            "<html>Page not found</html>"
        )));
        assert!(looks_like_error_page(&resp(
            200,
            Some("text/html"),
            "internal server error"
        )));
        // A very short HTML stub is discarded even with no error phrasing.
        assert!(looks_like_error_page(&resp(
            200,
            Some("text/html"),
            "<html></html>"
        )));
        // A JSON body of secrets is not an error page.
        assert!(!looks_like_error_page(&resp(
            200,
            Some("application/json"),
            r#"{"password":"x"}"#
        )));
    }

    // --- Catch-all (homepage) suppression --------------------------------------

    #[test]
    fn catch_all_homepage_is_not_exposed() {
        let homepage = resp(
            200,
            Some("text/html"),
            "<html><body>Welcome to Acme</body></html>",
        );
        let baseline = Baseline::from_response(&homepage);
        // A sensitive path that serves the exact homepage is a catch-all, not an
        // exposed admin interface.
        let verdict = evaluate("/admin", &homepage, Some(&baseline));
        assert_eq!(verdict, Verdict::NotExposed);
        // A distinct admin page is still flagged.
        let admin = resp(
            200,
            Some("text/html"),
            "<html><title>Admin Panel</title> secret_key=abcdefabcdef</html>",
        );
        assert!(matches!(
            evaluate("/admin", &admin, Some(&baseline)),
            Verdict::Exposed(_)
        ));
    }

    // --- Redirect resolution ---------------------------------------------------

    #[test]
    fn redirect_resolution_keeps_same_host_only() {
        let from = Url::parse("http://target.test/dashboard").unwrap();
        // Relative redirect resolves against the request URL.
        assert_eq!(
            resolve_same_host_redirect(&from, "/admin", Some("target.test"))
                .unwrap()
                .as_str(),
            "http://target.test/admin"
        );
        // Absolute redirect to the same host is kept.
        assert!(
            resolve_same_host_redirect(&from, "http://target.test/admin", Some("target.test"))
                .is_some()
        );
        // A redirect off-host is dropped (we scan only the requested origin).
        assert!(
            resolve_same_host_redirect(&from, "http://evil.test/admin", Some("target.test"))
                .is_none()
        );
    }

    // --- Finding construction (task 6.1) ---------------------------------------

    #[test]
    fn finding_carries_full_evidence() {
        let response = resp(
            200,
            Some("application/json"),
            r#"{"db_password":"hunter2"}"#,
        );
        let exposure = match evaluate("/api/admin", &response, None) {
            Verdict::Exposed(e) => e,
            other => panic!("expected exposed, got {other:?}"),
        };
        let url = Url::parse("https://example.com/api/admin").unwrap();
        let finding = build_finding(&target(), "/api/admin", &url, &response, &exposure, None);

        assert_eq!(finding.scanner_id, "bac");
        assert_eq!(finding.status, Status::Vulnerable);
        assert_eq!(finding.severity, Severity::Critical);
        assert!(finding.description.is_some());
        assert!(finding.recommendations.is_some());

        let evidence = finding.evidence.unwrap();
        assert_eq!(evidence["endpoint"], "/api/admin");
        assert_eq!(evidence["url"], "https://example.com/api/admin");
        assert_eq!(evidence["status"], 200);
        assert_eq!(evidence["endpoint_kind"], "admin");
        assert_eq!(evidence["data_class"], "credentials");
        assert!(evidence["exposure_signals"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "db_password"));
        assert_eq!(evidence["body_truncated"], false);
        assert!(evidence["response_sample"]
            .as_str()
            .unwrap()
            .contains("db_password"));
        // No redirect chain on a direct finding.
        assert!(evidence.get("redirected_from").is_none());
    }

    #[test]
    fn redirect_finding_records_its_source() {
        let response = resp(
            200,
            Some("text/html"),
            "<title>Admin Panel</title> secret_key=z",
        );
        let exposure = match evaluate("/admin/secret", &response, None) {
            Verdict::Exposed(e) => e,
            other => panic!("expected exposed, got {other:?}"),
        };
        let url = Url::parse("https://example.com/admin/secret").unwrap();
        let finding = build_finding(
            &target(),
            "/admin/secret",
            &url,
            &response,
            &exposure,
            Some("/dashboard"),
        );
        assert_eq!(finding.evidence.unwrap()["redirected_from"], "/dashboard");
        assert!(finding.title.contains("via redirect from /dashboard"));
    }

    #[test]
    fn bounded_sample_caps_length() {
        let big = "A".repeat(SAMPLE_BYTES * 4);
        assert_eq!(bounded_sample(big.as_bytes()).len(), SAMPLE_BYTES);
        assert_eq!(bounded_sample(b"short"), "short");
    }
}
