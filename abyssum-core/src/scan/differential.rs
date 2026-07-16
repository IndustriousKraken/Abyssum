//! Auth-differential scanning: run one surface under several named identities and
//! report where access diverges.
//!
//! BAC and IDOR already compare a credentialed baseline against a
//! credential-*stripped* request — one identity versus anonymous. A differential
//! scan compares two or more *real* identities against each other: user-A reaching
//! user-B's resources (horizontal), or an anonymous / lower-privilege caller
//! reaching a privileged endpoint (vertical).
//!
//! The flow is two phases, both routed through the shared, paced [`ScanContext`]
//! seam so no identity gets an aggression exemption:
//!
//! 1. **Per-identity pass** — run the selected scanners once per identity, with
//!    that identity's credential attached via [`Orchestrator::with_credential`].
//!    Each pass surfaces the resources it can reach; their union is the candidate
//!    set to compare.
//! 2. **Differential re-probe** — GET each candidate once per identity (this time
//!    keeping each identity's credential, so the response reflects that identity's
//!    view) and compare the responses.
//!
//! A resource served with equivalent, privileged content to two or more identities
//! is not properly scoped — a finding. A resource served only to its owning
//! identity and denied or differing for the others produces none. The comparison
//! reuses the false-positive guards proven in BAC/IDOR: a soft-error / login-page
//! fingerprint, and a whitespace-normalized body hash so that identical error or
//! sign-in pages are not mistaken for shared access.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use url::Url;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::rate_limiter::RateLimiter;
use crate::seed::RotatingUserAgent;

use super::context::{
    build_engine_http_client, Credential, RequestSpec, ScanContext, UserAgentSource,
};
use super::finding::{Finding, Severity, Status};
use super::orchestrator::Orchestrator;
use super::registry::ScannerRegistry;
use super::session::ScanSession;
use super::target::Target;

/// The stable scanner-id label carried by every differential finding. Findings are
/// otherwise ordinary — persisted, filtered, and rendered like any other.
pub const ID: &str = "auth_differential";

/// Upper bound on the response body buffered per re-probe. A probed endpoint is
/// untrusted and could stream an unbounded body, so bytes beyond this cap are
/// dropped and the response is flagged `truncated`.
const MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

/// How many leading bytes of the response body to keep as the bounded evidence
/// sample (UTF-8 lossy).
const SAMPLE_BYTES: usize = 512;

/// Largest body (bytes) the soft-error phrase scan inspects; a recognized
/// denied/not-found phrase is characteristic of short stub pages, so a large real
/// body that merely mentions one somewhere is not suppressed.
const ERROR_PAGE_MAX_BYTES: usize = 4096;

/// A named identity a scan runs as: a label plus an optional [`Credential`]. The
/// anonymous identity carries no credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The human-facing label naming this identity in findings.
    pub label: String,
    /// The credential attached to this identity's requests, or `None` for the
    /// anonymous identity.
    pub credential: Option<Credential>,
}

impl Identity {
    /// The anonymous identity: a label with no credential.
    pub fn anonymous(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            credential: None,
        }
    }

    /// A credentialed identity.
    pub fn credentialed(label: impl Into<String>, credential: Credential) -> Self {
        Self {
            label: label.into(),
            credential: Some(credential),
        }
    }

    /// Whether this identity carries no credential.
    pub fn is_anonymous(&self) -> bool {
        self.credential.is_none()
    }
}

/// Run a differential scan: run the selected scanners once per identity, then
/// re-probe every surfaced resource under each identity and report access-control
/// divergence. Returns the differential findings (the per-identity scanner passes
/// drive resource discovery and pacing; their own findings are not returned).
///
/// `make_registry` builds a fresh [`ScannerRegistry`] per identity — the caller
/// owns scanner registration (the core crate cannot reach the scanner crate), so it
/// passes a closure. Every per-identity orchestrator shares one rate limiter and
/// User-Agent source, so the pacing floor spans all identities.
///
/// `cancel` is the run's cancellation signal: when it fires (e.g. the CLI catches
/// Ctrl-C), each in-flight per-identity pass is cancelled and the re-probe loop
/// stops promptly, returning the findings gathered so far so a caller can still
/// persist the partial result.
pub async fn run_differential(
    config: Arc<Config>,
    make_registry: impl Fn() -> ScannerRegistry,
    targets: &[Target],
    scanner_ids: &[String],
    identities: &[Identity],
    cancel: CancellationToken,
) -> Result<Vec<Finding>> {
    // One shared pacing authority + UA source, so every identity's pass and the
    // differential re-probe route through the same per-host floor.
    let rate_limiter = RateLimiter::from_config(&config.scanning);
    let ua_source: Arc<dyn UserAgentSource> = Arc::new(RotatingUserAgent::new(
        Vec::new(),
        config.scanning.user_agent_rotation,
    ));
    // One HTTP client (connection pool) shared by every pass and every re-probe.
    let http = build_engine_http_client();

    // Phase 1: run the selected scanners once per identity (credential attached),
    // collecting the union of resources any identity's pass surfaced.
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for identity in identities {
        if cancel.is_cancelled() {
            break;
        }
        let mut orchestrator = Orchestrator::new(config.clone(), make_registry())
            .with_rate_limiter(rate_limiter.clone())
            .with_http_client(http.clone())
            .with_user_agent_source(ua_source.clone());
        if let Some(credential) = &identity.credential {
            orchestrator = orchestrator.with_credential(credential.clone());
        }
        let session = run_identity_pass(&orchestrator, targets, scanner_ids, &cancel).await?;
        for candidate in extract_candidates(&session.findings) {
            if seen.insert(candidate.url.as_str().to_string()) {
                candidates.push(candidate);
            }
        }
    }

    // Phase 2: re-probe each candidate once per identity and compare.
    let mut findings = Vec::new();
    for candidate in &candidates {
        if cancel.is_cancelled() {
            break;
        }
        if let Some(finding) = diff_one_resource(
            &candidate.target,
            &candidate.url,
            identities,
            &config,
            &rate_limiter,
            &ua_source,
            &http,
            &cancel,
        )
        .await
        {
            findings.push(finding);
        }
    }

    Ok(findings)
}

/// Run one per-identity scanner pass to a terminal state, cancelling it promptly if
/// `cancel` fires. The orchestrator owns its own session token, so bridge the
/// external run token to it via [`Orchestrator::cancel`] — the same shape as the
/// CLI's `run_to_completion`, which the ordinary scan path uses to honor Ctrl-C.
async fn run_identity_pass(
    orchestrator: &Orchestrator,
    targets: &[Target],
    scanner_ids: &[String],
    cancel: &CancellationToken,
) -> Result<ScanSession> {
    let handle = orchestrator.create_session(targets.to_vec(), scanner_ids.to_vec())?;
    let session_id = handle.lock().expect("session handle not poisoned").id;
    let run = orchestrator.run(session_id, None);
    tokio::pin!(run);
    let mut signalled = false;
    loop {
        tokio::select! {
            biased;
            result = &mut run => return result,
            // Fire once: cancel the running session, then keep awaiting the run,
            // which returns its (Cancelled) partial session promptly.
            _ = cancel.cancelled(), if !signalled => {
                signalled = true;
                let _ = orchestrator.cancel(session_id);
            }
        }
    }
}

/// A resource surfaced by a per-identity pass: the scan target it belongs to and
/// its concrete URL.
#[derive(Debug, Clone)]
struct Candidate {
    target: Target,
    url: Url,
}

/// Extract the resources named by a pass's findings: an evidence `url`, or an
/// evidence `path`/`endpoint` joined against the finding's target origin. Findings
/// with no resource-bearing evidence contribute nothing (the target origin itself is
/// deliberately not a candidate — a homepage served identically to everyone is not a
/// scoping failure).
fn extract_candidates(findings: &[Finding]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for finding in findings {
        let Some(evidence) = &finding.evidence else {
            continue;
        };
        let url = evidence
            .get("url")
            .and_then(|v| v.as_str())
            .and_then(|s| Url::parse(s).ok())
            .or_else(|| {
                evidence
                    .get("path")
                    .or_else(|| evidence.get("endpoint"))
                    .and_then(|v| v.as_str())
                    .and_then(|path| finding.target.base_url().join(path).ok())
            });
        if let Some(url) = url {
            out.push(Candidate {
                target: finding.target.clone(),
                url,
            });
        }
    }
    out
}

/// Probe one resource once per identity through a paced, credentialed context and
/// compare the views. Returns a finding when two or more identities receive
/// equivalent privileged content.
#[allow(clippy::too_many_arguments)]
async fn diff_one_resource(
    target: &Target,
    url: &Url,
    identities: &[Identity],
    config: &Arc<Config>,
    rate_limiter: &RateLimiter,
    ua_source: &Arc<dyn UserAgentSource>,
    http: &reqwest::Client,
    cancel: &CancellationToken,
) -> Option<Finding> {
    let mut views = Vec::with_capacity(identities.len());
    for identity in identities {
        let mut ctx = ScanContext::new(
            config.clone(),
            rate_limiter.clone(),
            ua_source.clone(),
            cancel.clone(),
        )
        .with_http_client(http.clone());
        if let Some(credential) = &identity.credential {
            ctx = ctx.with_credential(credential.clone());
        }
        // Race the probe against cancellation so an in-flight request unwinds
        // promptly on Ctrl-C; a transport failure for one identity drops only that
        // identity's view, and the others still compare.
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            result = probe(&ctx, url.clone()) => {
                if let Ok(probe) = result {
                    views.push(ResourceView {
                        identity: identity.label.clone(),
                        status: probe.status,
                        body: probe.body,
                        truncated: probe.truncated,
                    });
                }
            }
        }
    }
    compare(target, url, &views)
}

/// One identity's observed response to one resource.
#[derive(Debug, Clone)]
struct ResourceView {
    identity: String,
    status: u16,
    body: Vec<u8>,
    truncated: bool,
}

/// Whether a view represents privileged access to a real resource: a 2xx status, a
/// non-empty body, and not a recognized soft-error / login page. A denied identity
/// (401/403), an empty stub, or a "please sign in" page does not count.
fn is_privileged(view: &ResourceView) -> bool {
    (200..300).contains(&view.status) && !view.body.is_empty() && !looks_like_error_page(view)
}

/// Compare identities' views of one resource. Emits a finding when two or more
/// distinct identities received equivalent privileged content (the same
/// normalized body) — the resource is reachable by identities that should not all
/// share it. When each identity saw distinct content, or was denied, the resource
/// is properly scoped and no finding is emitted.
///
/// Pure over its inputs, so the whole decision is unit-testable without a network.
fn compare(target: &Target, url: &Url, views: &[ResourceView]) -> Option<Finding> {
    let privileged: Vec<&ResourceView> = views.iter().filter(|v| is_privileged(v)).collect();
    if privileged.len() < 2 {
        return None;
    }

    // Cluster the privileged views by normalized body: identities served the same
    // content land in the same group. A group holding two or more distinct
    // identities is shared access to a resource that should be scoped.
    let mut groups: HashMap<u64, BTreeSet<String>> = HashMap::new();
    for view in &privileged {
        groups
            .entry(normalized_body_hash(&view.body))
            .or_default()
            .insert(view.identity.clone());
    }

    // Pick the largest shared group. HashMap iteration order is randomized and
    // `max_by_key` returns the *last* maximum, so ties would make the reported
    // finding non-deterministic across runs; break them by the identity set (each
    // identity lands in exactly one group, so the sets are disjoint and this is a
    // total order) to keep the evidence reproducible.
    let (hash, shared) = groups
        .iter()
        .filter(|(_, identities)| identities.len() >= 2)
        .max_by(|(_, a), (_, b)| a.len().cmp(&b.len()).then_with(|| b.cmp(a)))?;

    // A representative privileged view from the shared group carries the sample and
    // status for the evidence.
    let rep = privileged
        .iter()
        .find(|v| normalized_body_hash(&v.body) == *hash)?;

    Some(build_finding(target, url, shared, rep))
}

/// Build the differential [`Finding`]: a Vulnerable, high-severity access-control
/// divergence naming the resource and the identities that could all reach it.
fn build_finding(
    target: &Target,
    url: &Url,
    identities: &BTreeSet<String>,
    rep: &ResourceView,
) -> Finding {
    let id_list = identities
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let title = format!(
        "Access-control divergence: {} reachable by multiple identities ({id_list})",
        url.path()
    );
    let description = format!(
        "GET {} returned equivalent privileged content (HTTP {}) to identities {id_list}. A \
         resource that should be scoped to a single identity is reachable by more than one — a \
         horizontal (one identity reads another's resource) or vertical (a lower-privilege or \
         anonymous identity reaches a privileged endpoint) broken-access-control failure.",
        url.as_str(),
        rep.status,
    );
    let evidence = serde_json::json!({
        "resource": url.as_str(),
        "status": rep.status,
        "identities": identities.iter().collect::<Vec<_>>(),
        "shared_response_sample": bounded_sample(&rep.body),
        "body_length": rep.body.len(),
        "body_truncated": rep.truncated,
    });

    Finding::builder(ID, target.clone(), title)
        .status(Status::Vulnerable)
        .severity(Severity::High)
        .description(description)
        .evidence(evidence)
        .recommendations(
            "Enforce per-identity authorization server-side: every request must verify the \
             authenticated caller is permitted to access that specific resource, not merely that \
             they are authenticated. Reject requests from identities that do not own the resource \
             with 401/403, and require authentication on privileged endpoints.",
        )
        .build()
}

/// A re-probe's response reduced to the fields the comparison needs.
struct Probe {
    status: u16,
    body: Vec<u8>,
    truncated: bool,
}

/// GET one URL through the paced scan context (keeping the context's credential, so
/// the response reflects the identity's view), buffering at most [`MAX_BODY_BYTES`].
async fn probe(ctx: &ScanContext, url: Url) -> Result<Probe> {
    let mut response = ctx.send(RequestSpec::get(url)).await?;
    let status = response.status().as_u16();

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

    Ok(Probe {
        status,
        body,
        truncated,
    })
}

/// Whether a 2xx body is a recognized soft-error / not-found / access-denied /
/// login page returned with a success status — content that must not be mistaken
/// for shared access. Gated on a modest body length.
fn looks_like_error_page(view: &ResourceView) -> bool {
    const PHRASES: &[&str] = &[
        "not found",
        "no longer exists",
        "does not exist",
        "cannot be found",
        "resource not found",
        "unauthorized",
        "forbidden",
        "access denied",
        "permission denied",
        "not authorized",
        "please log in",
        "please sign in",
        "sign in to continue",
        "login required",
        "authentication required",
    ];
    if view.truncated || view.body.len() > ERROR_PAGE_MAX_BYTES {
        return false;
    }
    let lower = String::from_utf8_lossy(&view.body).to_ascii_lowercase();
    PHRASES.iter().any(|p| lower.contains(p))
}

/// Hash of a response body after collapsing whitespace runs to single spaces and
/// trimming, so trivial formatting differences do not defeat the equivalence check.
///
/// Uses [`std::collections::hash_map::DefaultHasher`], whose output is not stable
/// across Rust versions — safe here because every body compared is hashed within
/// one differential run; this value MUST NOT be persisted or compared across runs.
fn normalized_body_hash(body: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let text = String::from_utf8_lossy(body);
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    normalized.hash(&mut hasher);
    hasher.finish()
}

/// Keep at most [`SAMPLE_BYTES`] leading bytes of `body` as a UTF-8 lossy evidence
/// sample, never the whole (possibly large) body.
fn bounded_sample(body: &[u8]) -> String {
    let end = body.len().min(SAMPLE_BYTES);
    String::from_utf8_lossy(&body[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target::parse("https://example.com").unwrap()
    }

    fn url() -> Url {
        Url::parse("https://example.com/api/users/1").unwrap()
    }

    fn view(identity: &str, status: u16, body: &str) -> ResourceView {
        ResourceView {
            identity: identity.to_string(),
            status,
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    // --- Identity ------------------------------------------------------------

    #[test]
    fn anonymous_and_credentialed_identities() {
        let anon = Identity::anonymous("guest");
        assert!(anon.is_anonymous());
        let alice = Identity::credentialed("alice", Credential::bearer("t"));
        assert!(!alice.is_anonymous());
        assert_eq!(alice.credential.unwrap().bearer.as_deref(), Some("t"));
    }

    // --- Comparator: the task-6 cases ----------------------------------------

    /// Identity-B reads identity-A's resource (equivalent privileged content served
    /// to both) → a finding naming the resource and both identities.
    #[test]
    fn cross_identity_access_is_reported() {
        let alice_data = r#"{"id":1,"owner":"alice","balance":4200}"#;
        // Both identities are served Alice's record.
        let views = [view("alice", 200, alice_data), view("bob", 200, alice_data)];
        let finding = compare(&target(), &url(), &views).expect("shared access is a finding");
        assert_eq!(finding.scanner_id, ID);
        assert_eq!(finding.status, Status::Vulnerable);
        assert_eq!(finding.severity, Severity::High);
        let identities = finding.evidence.as_ref().unwrap()["identities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert!(identities.contains(&"alice".to_string()));
        assert!(identities.contains(&"bob".to_string()));
        assert!(finding.title.contains("/api/users/1"));
    }

    /// A properly scoped resource — each identity served its own distinct record —
    /// produces no finding.
    #[test]
    fn properly_scoped_resource_is_not_reported() {
        let views = [
            view("alice", 200, r#"{"id":1,"owner":"alice","balance":4200}"#),
            view("bob", 200, r#"{"id":2,"owner":"bob","balance":17}"#),
        ];
        assert!(compare(&target(), &url(), &views).is_none());
    }

    /// A resource denied to the other identity (403) is properly scoped — no
    /// finding, even though one identity can read it.
    #[test]
    fn denied_other_identity_is_not_reported() {
        let views = [
            view("alice", 200, r#"{"id":1,"owner":"alice"}"#),
            view("bob", 403, r#"{"error":"forbidden"}"#),
        ];
        assert!(compare(&target(), &url(), &views).is_none());
    }

    /// The anonymous identity reaching a privileged endpoint that an authenticated
    /// identity also reaches (equivalent content) → a vertical finding.
    #[test]
    fn anonymous_access_to_privileged_endpoint_is_reported() {
        let admin = r#"{"users":[{"id":1},{"id":2}],"role":"admin"}"#;
        let views = [
            view("admin-user", 200, admin),
            view("anonymous", 200, admin),
        ];
        let finding = compare(&target(), &url(), &views).expect("anonymous vertical access");
        assert!(finding
            .evidence
            .as_ref()
            .unwrap()
            .to_string()
            .contains("anonymous"));
    }

    /// Two identities served the same *login / denied* page are not mistaken for
    /// shared access — the soft-error guard suppresses it.
    #[test]
    fn identical_login_pages_are_not_shared_access() {
        let login = "<html><body>Please sign in to continue</body></html>";
        let views = [view("alice", 200, login), view("bob", 200, login)];
        assert!(compare(&target(), &url(), &views).is_none());
    }

    /// Whitespace-only formatting differences still count as equivalent content.
    #[test]
    fn normalized_bodies_ignore_whitespace() {
        let views = [
            view("alice", 200, r#"{"id":1,  "owner":"alice"}"#),
            view("bob", 200, "{\"id\":1,\n\t\"owner\":\"alice\"}"),
        ];
        assert!(compare(&target(), &url(), &views).is_some());
    }

    /// When two shared-content groups tie on size, the reported finding is
    /// deterministic across runs (HashMap iteration order is randomized, so a fresh
    /// `compare` runs against a fresh map each iteration). The tie is broken by the
    /// identity set, so the lexicographically-smaller group ({alice, bob}) always
    /// wins over the equal-sized {carol, dave}.
    #[test]
    fn tied_shared_groups_pick_deterministically() {
        let ab = r#"{"shared":"one"}"#;
        let cd = r#"{"shared":"two"}"#;
        let views = [
            view("alice", 200, ab),
            view("bob", 200, ab),
            view("carol", 200, cd),
            view("dave", 200, cd),
        ];
        for _ in 0..50 {
            let finding = compare(&target(), &url(), &views).expect("a shared group is a finding");
            let ids = finding.evidence.as_ref().unwrap()["identities"].to_string();
            assert!(
                ids.contains("alice") && ids.contains("bob"),
                "the smaller tied group must win every run; got {ids}"
            );
            assert!(
                !ids.contains("carol"),
                "the losing group must not appear: {ids}"
            );
        }
    }

    /// A single privileged identity (the others denied/absent) is not a finding.
    #[test]
    fn single_privileged_identity_is_not_reported() {
        let views = [
            view("alice", 200, r#"{"id":1,"owner":"alice"}"#),
            view("bob", 404, "not found"),
        ];
        assert!(compare(&target(), &url(), &views).is_none());
    }

    // --- Candidate extraction ------------------------------------------------

    #[test]
    fn extract_candidates_reads_url_and_path_evidence() {
        let t = Target::parse("https://example.com").unwrap();
        let with_url = Finding::builder("bac", t.clone(), "x")
            .evidence(serde_json::json!({ "url": "https://example.com/admin" }))
            .build();
        let with_path = Finding::builder("rest_discovery", t.clone(), "y")
            .evidence(serde_json::json!({ "path": "/api/users/1" }))
            .build();
        let no_resource = Finding::builder("cors", t.clone(), "z")
            .evidence(serde_json::json!({ "misconfiguration": "wildcard" }))
            .build();
        let candidates = extract_candidates(&[with_url, with_path, no_resource]);
        let urls: Vec<String> = candidates
            .iter()
            .map(|c| c.url.as_str().to_string())
            .collect();
        assert!(urls.contains(&"https://example.com/admin".to_string()));
        assert!(urls.contains(&"https://example.com/api/users/1".to_string()));
        // The finding with no resource-bearing evidence contributes nothing.
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn normalized_hash_matches_on_whitespace_only_difference() {
        assert_eq!(
            normalized_body_hash(b"hello   world\n"),
            normalized_body_hash(b"hello world")
        );
        assert_ne!(normalized_body_hash(b"alice"), normalized_body_hash(b"bob"));
    }

    /// A run whose cancellation token is already fired short-circuits: phase 1
    /// breaks before any pass runs and the call returns `Ok` with the (empty)
    /// partial findings rather than hanging or erroring — the property the CLI's
    /// Ctrl-C race relies on to persist a partial differential result.
    #[tokio::test]
    async fn cancelled_run_returns_partial_findings() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let targets = [Target::parse("https://example.com").unwrap()];
        let scanner_ids = ["rest_discovery".to_string()];
        let identities = [Identity::anonymous("a"), Identity::anonymous("b")];
        let findings = run_differential(
            Arc::new(Config::default()),
            || ScannerRegistry::new(Arc::new(Config::default())),
            &targets,
            &scanner_ids,
            &identities,
            cancel,
        )
        .await
        .expect("a cancelled run still returns Ok with the partial findings");
        assert!(
            findings.is_empty(),
            "a pre-cancelled run probes nothing, so it finds nothing"
        );
    }
}

/// End-to-end coverage of the re-probe + comparison over real HTTP: a mock server
/// routes on the request's bearer token, so the differential's per-identity
/// credentialed probing is exercised for real (task 6).
#[cfg(test)]
mod integration {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use crate::scan::context::SingleUserAgent;

    /// How a mock path answers: the same for every caller, or per bearer token with
    /// a fallback for an unknown/absent token.
    #[derive(Clone)]
    enum Responder {
        /// The same content regardless of credential (a resource anyone can read).
        Shared { status: u16, body: String },
        /// Distinct content per bearer token, with a default for others.
        ByBearer {
            by_token: HashMap<String, (u16, String)>,
            default: (u16, String),
        },
    }

    impl Responder {
        fn answer(&self, bearer: Option<&str>) -> (u16, String) {
            match self {
                Responder::Shared { status, body } => (*status, body.clone()),
                Responder::ByBearer { by_token, default } => bearer
                    .and_then(|t| by_token.get(t))
                    .cloned()
                    .unwrap_or_else(|| default.clone()),
            }
        }
    }

    async fn start_mock(routes: HashMap<String, Responder>) -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = Url::parse(&format!("http://{addr}/")).unwrap();
        tokio::spawn(async move {
            loop {
                let (sock, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => break,
                };
                let routes = routes.clone();
                tokio::spawn(async move { handle(sock, routes).await });
            }
        });
        base
    }

    async fn handle(mut sock: TcpStream, routes: HashMap<String, Responder>) {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = match sock.read(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
                break;
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let path = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap_or("/")
            .split('?')
            .next()
            .unwrap_or("/")
            .to_string();
        let bearer = head.lines().skip(1).find_map(|line| {
            let (k, v) = line.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("authorization") {
                v.trim().strip_prefix("Bearer ").map(str::to_string)
            } else {
                None
            }
        });

        let (status, body) = routes
            .get(&path)
            .map(|r| r.answer(bearer.as_deref()))
            .unwrap_or((404, "not found".to_string()));
        let response = format!(
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
        let _ = sock.write_all(response.as_bytes()).await;
        let _ = sock.shutdown().await;
    }

    fn identities() -> Vec<Identity> {
        vec![
            Identity::credentialed("alice", Credential::bearer("alice-tok")),
            Identity::credentialed("bob", Credential::bearer("bob-tok")),
        ]
    }

    async fn diff(base: &Url, path: &str) -> Option<Finding> {
        let config = Arc::new(Config::default());
        let rate_limiter = RateLimiter::new(Duration::ZERO, Duration::ZERO);
        let ua: Arc<dyn UserAgentSource> = Arc::new(SingleUserAgent::default());
        let http = build_engine_http_client();
        let cancel = CancellationToken::new();
        let target = Target::new(base.clone(), None, None);
        let url = base.join(path).unwrap();
        diff_one_resource(
            &target,
            &url,
            &identities(),
            &config,
            &rate_limiter,
            &ua,
            &http,
            &cancel,
        )
        .await
    }

    /// A surface where identity-B can read identity-A's resource (the endpoint
    /// serves the same privileged body to both) yields a finding naming both.
    #[tokio::test]
    async fn shared_resource_across_identities_is_reported() {
        let alice = r#"{"id":1,"owner":"alice","secret":"a"}"#;
        let mut routes = HashMap::new();
        routes.insert(
            "/api/users/1".to_string(),
            Responder::Shared {
                status: 200,
                body: alice.to_string(),
            },
        );
        let base = start_mock(routes).await;

        let finding = diff(&base, "/api/users/1")
            .await
            .expect("a shared resource is a differential finding");
        assert_eq!(finding.scanner_id, ID);
        assert_eq!(finding.status, Status::Vulnerable);
        let ids = finding.evidence.as_ref().unwrap()["identities"].to_string();
        assert!(ids.contains("alice") && ids.contains("bob"), "{ids}");
    }

    /// A properly scoped resource — each identity served its own distinct record,
    /// and a third path where the other identity is denied — yields no finding.
    #[tokio::test]
    async fn scoped_and_denied_resources_are_not_reported() {
        let mut by_token = HashMap::new();
        by_token.insert(
            "alice-tok".to_string(),
            (200, r#"{"id":1,"owner":"alice"}"#.to_string()),
        );
        by_token.insert(
            "bob-tok".to_string(),
            (200, r#"{"id":2,"owner":"bob"}"#.to_string()),
        );
        let mut routes = HashMap::new();
        routes.insert(
            "/api/account".to_string(),
            Responder::ByBearer {
                by_token,
                default: (403, r#"{"error":"forbidden"}"#.to_string()),
            },
        );
        // /admin: only alice may read it; bob is denied (403).
        let mut admin = HashMap::new();
        admin.insert(
            "alice-tok".to_string(),
            (200, r#"{"users":[1,2,3],"role":"admin"}"#.to_string()),
        );
        routes.insert(
            "/admin".to_string(),
            Responder::ByBearer {
                by_token: admin,
                default: (403, r#"{"error":"forbidden"}"#.to_string()),
            },
        );
        let base = start_mock(routes).await;

        assert!(
            diff(&base, "/api/account").await.is_none(),
            "each identity sees its own record — properly scoped"
        );
        assert!(
            diff(&base, "/admin").await.is_none(),
            "the other identity is denied — properly scoped"
        );
    }
}
