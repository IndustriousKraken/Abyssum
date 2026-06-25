//! Integration tests for the Broken Access Control (BAC) scanner.
//!
//! Every test runs against a hand-rolled, in-process mock HTTP server bound to a
//! random localhost port — **no real targets, no external deps**. The mock maps
//! exact paths to canned responses (status, content-type, body, and an optional
//! `Location` for redirects), records each request's path, arrival instant, and
//! whether it carried an `Authorization` or `Cookie` header (so the
//! credential-stripping test can assert their absence), and can fire a cancellation
//! token after the Nth request so the cancellation test is deterministic. Responses
//! close the connection (`Connection: close`), so each request is one fresh
//! connection the handler serves once.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

use abyssum_core::{
    BaseScanner, Config, Credential, DatabaseManager, Orchestrator, RateLimiter, ScanContext,
    ScannerRegistry, SessionStatus, Severity, SingleUserAgent, Status, Target,
};
use abyssum_scanners::{register_builtins, BacScanner};

// --- Mock HTTP server -------------------------------------------------------

/// A canned response for a path (or the catch-all default).
#[derive(Clone)]
struct Route {
    status: u16,
    content_type: String,
    body: String,
    /// An optional `Location` header value (for redirects).
    location: Option<String>,
}

impl Route {
    fn new(status: u16, content_type: &str, body: &str) -> Self {
        Self {
            status,
            content_type: content_type.to_string(),
            body: body.to_string(),
            location: None,
        }
    }
    fn json(body: &str) -> Self {
        Self::new(200, "application/json", body)
    }
    fn html(body: &str) -> Self {
        Self::new(200, "text/html", body)
    }
    fn not_found(body: &str) -> Self {
        Self::new(404, "text/plain", body)
    }
    fn redirect_to(location: &str) -> Self {
        Self {
            status: 302,
            content_type: "text/html".to_string(),
            body: String::new(),
            location: Some(location.to_string()),
        }
    }
}

/// One recorded request: its path, the instant it arrived, and whether it carried
/// authorization / cookie credentials.
struct Hit {
    path: String,
    at: Instant,
    had_authorization: bool,
    had_cookie: bool,
}

/// A running mock server: its base URL and the recorded request log.
struct Mock {
    base: Url,
    hits: Arc<Mutex<Vec<Hit>>>,
}

impl Mock {
    fn target(&self) -> Target {
        Target::new(self.base.clone(), None, None)
    }
}

/// Start a mock server on a random localhost port. `routes` maps exact paths to
/// responses; unknown paths get `default`. If `cancel_after` is set, the server
/// fires the token once it has received that many requests (before responding), so
/// a scanner observes cancellation on its next loop check.
async fn start_mock(
    routes: HashMap<String, Route>,
    default: Route,
    cancel_after: Option<(usize, CancellationToken)>,
) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = Url::parse(&format!("http://{addr}/")).unwrap();
    let hits = Arc::new(Mutex::new(Vec::new()));
    let hits_bg = hits.clone();

    tokio::spawn(async move {
        loop {
            let (sock, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let routes = routes.clone();
            let default = default.clone();
            let hits = hits_bg.clone();
            let cancel_after = cancel_after.clone();
            tokio::spawn(async move {
                handle_conn(sock, routes, default, hits, cancel_after).await;
            });
        }
    });

    Mock { base, hits }
}

async fn handle_conn(
    mut sock: TcpStream,
    routes: HashMap<String, Route>,
    default: Route,
    hits: Arc<Mutex<Vec<Hit>>>,
    cancel_after: Option<(usize, CancellationToken)>,
) {
    let head = match read_request_head(&mut sock).await {
        Some(head) => head,
        None => return,
    };
    let path = request_path(&head);
    let had_authorization = header_in(&head, "authorization").is_some();
    let had_cookie = header_in(&head, "cookie").is_some();

    let count = {
        let mut log = hits.lock().unwrap();
        log.push(Hit {
            path: path.clone(),
            at: Instant::now(),
            had_authorization,
            had_cookie,
        });
        log.len()
    };

    // Fire cancellation before responding, so the in-flight scan sees it next.
    if let Some((n, token)) = &cancel_after {
        if count >= *n {
            token.cancel();
        }
    }

    let route = routes.get(&path).cloned().unwrap_or(default);
    let location_header = match &route.location {
        Some(loc) => format!("Location: {loc}\r\n"),
        None => String::new(),
    };
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n{}",
        route.status,
        reason_phrase(route.status),
        route.content_type,
        route.body.len(),
        location_header,
        route.body,
    );
    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.flush().await;
    let _ = sock.shutdown().await;
}

/// Read the request head (up to the blank-line terminator). GET carries no body, so
/// the header terminator is sufficient.
async fn read_request_head(sock: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }
    Some(String::from_utf8_lossy(&buf).to_string())
}

/// Recover the request path (without query string) from a raw request head.
fn request_path(head: &str) -> String {
    let first_line = head.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let _method = parts.next();
    let request_target = parts.next().unwrap_or("/");
    request_target
        .split('?')
        .next()
        .unwrap_or(request_target)
        .to_string()
}

/// Extract a header value (case-insensitive name) from a raw request head.
fn header_in(head: &str, name: &str) -> Option<String> {
    for line in head.lines().skip(1) {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().eq_ignore_ascii_case(name) {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        302 => "Found",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

// --- Direct-scan helpers ----------------------------------------------------

fn ctx_with(rate: RateLimiter, cancel: CancellationToken) -> ScanContext {
    ScanContext::new(
        Arc::new(Config::default()),
        rate,
        Arc::new(SingleUserAgent::default()),
        cancel,
    )
}

fn no_pacing() -> RateLimiter {
    RateLimiter::new(Duration::ZERO, Duration::ZERO)
}

// --- Tests ------------------------------------------------------------------

/// Task 7.2 + spec: against a server with an exposed admin endpoint, a properly
/// protected endpoint (401), an absent endpoint (404), and a redirect-to-admin
/// chain, the scanner flags exactly the exposed endpoint and the reachable redirect
/// target — and nothing else.
#[tokio::test]
async fn flags_exposed_and_reachable_redirect_target_only() {
    let mut routes = HashMap::new();
    // A benign homepage (the baseline catch-all fingerprint).
    routes.insert("/".to_string(), Route::html("<html>Welcome to Acme</html>"));
    // Exposed: an admin endpoint dumping credentials → critical.
    routes.insert(
        "/admin".to_string(),
        Route::json(r#"{"db_password":"hunter2","admin":true}"#),
    );
    // Properly protected (401, not 403 — 403 trips the limiter's distress backoff).
    routes.insert(
        "/api/users".to_string(),
        Route::new(401, "application/json", r#"{"error":"unauthorized"}"#),
    );
    // A redirect chain: /dashboard -> /admin/secret, which is itself exposed.
    routes.insert(
        "/dashboard".to_string(),
        Route::redirect_to("/admin/secret"),
    );
    routes.insert(
        "/admin/secret".to_string(),
        Route::html("<title>Admin Panel</title> secret_key=abcdef0123456789"),
    );
    let mock = start_mock(routes, Route::not_found("not found"), None).await;

    // /manage is absent (404 default); the four named candidates plus the absent one.
    let scanner = BacScanner::with_paths(["/admin", "/api/users", "/manage", "/dashboard"]);
    let findings = scanner
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    assert_eq!(
        findings.len(),
        2,
        "exactly the exposed admin endpoint and the reachable redirect target: {findings:#?}"
    );
    assert!(findings.iter().all(|f| f.scanner_id == "bac"));
    assert!(findings.iter().all(|f| f.status == Status::Vulnerable));

    // The directly-exposed admin endpoint: critical (credentials), full evidence.
    let admin = findings
        .iter()
        .find(|f| f.evidence.as_ref().unwrap()["endpoint"] == "/admin")
        .expect("the exposed /admin endpoint is reported");
    assert_eq!(admin.severity, Severity::Critical);
    let admin_evidence = admin.evidence.as_ref().unwrap();
    assert_eq!(admin_evidence["status"], 200);
    assert_eq!(admin_evidence["endpoint_kind"], "admin");
    assert_eq!(admin_evidence["data_class"], "credentials");
    assert!(admin_evidence.get("redirected_from").is_none());

    // The redirect target reached from /dashboard is flagged, recording its source.
    let redirected = findings
        .iter()
        .find(|f| f.evidence.as_ref().unwrap()["endpoint"] == "/admin/secret")
        .expect("the reachable redirect target is reported");
    assert_eq!(
        redirected.evidence.as_ref().unwrap()["redirected_from"],
        "/dashboard"
    );

    // Neither the protected (401) nor the absent (404) endpoint is reported.
    assert!(findings
        .iter()
        .all(|f| f.evidence.as_ref().unwrap()["endpoint"] != "/api/users"));
    assert!(findings
        .iter()
        .all(|f| f.evidence.as_ref().unwrap()["endpoint"] != "/manage"));
}

/// Spec "Redirect target requires authentication": a sensitive path that redirects
/// to a sensitive location which itself requires auth is not a finding.
#[tokio::test]
async fn protected_redirect_target_is_not_a_finding() {
    let mut routes = HashMap::new();
    routes.insert("/dashboard".to_string(), Route::redirect_to("/admin"));
    // The redirect target is properly protected.
    routes.insert(
        "/admin".to_string(),
        Route::new(401, "application/json", r#"{"error":"unauthorized"}"#),
    );
    let mock = start_mock(routes, Route::not_found("nf"), None).await;

    let scanner = BacScanner::with_paths(["/dashboard"]);
    let findings = scanner
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    assert!(
        findings.is_empty(),
        "a redirect to a protected target is not a finding: {findings:#?}"
    );
}

/// Task 7.3 + spec "Probes are sent without credentials": even when the scan context
/// carries a credential, every probe (including the baseline and any redirect
/// follow-up) is issued with no `Authorization` and no `Cookie`.
#[tokio::test]
async fn every_probe_is_sent_without_credentials() {
    let mut routes = HashMap::new();
    routes.insert("/".to_string(), Route::html("<html>home</html>"));
    routes.insert("/admin".to_string(), Route::json(r#"{"password":"x"}"#));
    routes.insert(
        "/dashboard".to_string(),
        Route::redirect_to("/admin/secret"),
    );
    routes.insert(
        "/admin/secret".to_string(),
        Route::html("<title>Admin Panel</title> secret_key=zzzz"),
    );
    let mock = start_mock(routes, Route::not_found("nf"), None).await;

    let scanner = BacScanner::with_paths(["/admin", "/dashboard"]);
    // The context carries BOTH a bearer token and a cookie; neither must leak.
    let ctx = ctx_with(no_pacing(), CancellationToken::new()).with_credential(Credential {
        bearer: Some("super-secret-token".to_string()),
        cookie: Some("session=abc123".to_string()),
    });
    let findings = scanner.scan(&mock.target(), &ctx).await.unwrap();
    assert!(
        !findings.is_empty(),
        "the exposed endpoints are still found"
    );

    let hits = mock.hits.lock().unwrap();
    assert!(
        hits.len() >= 4,
        "baseline + two candidates + one redirect follow-up: {}",
        hits.len()
    );
    assert!(
        hits.iter().all(|h| !h.had_authorization),
        "no probe may carry an Authorization header"
    );
    assert!(
        hits.iter().all(|h| !h.had_cookie),
        "no probe may carry a Cookie header"
    );
}

/// Task 7.4 + spec "Stops promptly on cancellation": cancellation halts further
/// requests and the scan returns the findings gathered so far.
#[tokio::test]
async fn cancellation_stops_promptly_and_returns_partial_results() {
    let cancel = CancellationToken::new();
    let mut routes = HashMap::new();
    routes.insert("/admin".to_string(), Route::json(r#"{"password":"x"}"#));
    // Cancel once the server has seen 2 requests: the baseline (#1) and the first
    // candidate, /admin (#2).
    let mock = start_mock(routes, Route::not_found("nf"), Some((2, cancel.clone()))).await;

    let scanner = BacScanner::with_paths(["/admin", "/manage", "/internal", "/logs", "/settings"]);
    let findings = scanner
        .scan(&mock.target(), &ctx_with(no_pacing(), cancel.clone()))
        .await
        .expect("cancellation yields Ok with partial findings, not an error");

    assert_eq!(
        findings.len(),
        1,
        "only /admin was probed before cancellation: {findings:#?}"
    );
    assert_eq!(findings[0].evidence.as_ref().unwrap()["endpoint"], "/admin");

    let hits = mock.hits.lock().unwrap();
    assert_eq!(
        hits.len(),
        2,
        "baseline + one probe; cancellation halted the remaining paths"
    );
    // The baseline hits the origin; the one probed candidate is /admin.
    assert_eq!(hits[0].path, "/");
    assert_eq!(hits[1].path, "/admin");
}

/// Task 7.5 + spec "Respects the configured pacing floor": every request after the
/// first (free) one trails its predecessor by at least the floor.
#[tokio::test]
async fn requests_are_paced_through_the_rate_limiter() {
    let mock = start_mock(HashMap::new(), Route::not_found("nf"), None).await;
    let floor = Duration::from_millis(60);
    // min == max removes base randomness, so each paced gap is exactly the floor.
    let scanner = BacScanner::with_paths(["/admin", "/manage", "/internal"]);
    scanner
        .scan(
            &mock.target(),
            &ctx_with(RateLimiter::new(floor, floor), CancellationToken::new()),
        )
        .await
        .unwrap();

    let hits = mock.hits.lock().unwrap();
    assert_eq!(hits.len(), 4, "baseline + three probes");
    // First request (the baseline) is free; every later request must trail the
    // previous by at least the floor (small slack for measurement granularity).
    for pair in hits.windows(2) {
        let gap = pair[1].at.duration_since(pair[0].at);
        assert!(
            gap >= floor - Duration::from_millis(10),
            "a request was issued before the pacing floor elapsed: gap {gap:?} < floor {floor:?}"
        );
    }
}

/// Task 3.4 + spec "Reports progress": the scanner emits a progress update per
/// probed candidate (tested / total / current path).
#[tokio::test]
async fn emits_progress_per_candidate() {
    let mock = start_mock(HashMap::new(), Route::not_found("nf"), None).await;
    let updates = Arc::new(Mutex::new(Vec::new()));
    let sink = updates.clone();
    let ctx = ctx_with(no_pacing(), CancellationToken::new())
        .with_progress(Arc::new(move |u| sink.lock().unwrap().push(u)));

    let scanner = BacScanner::with_paths(["/admin", "/manage", "/internal"]);
    scanner.scan(&mock.target(), &ctx).await.unwrap();

    let updates = updates.lock().unwrap();
    assert_eq!(updates.len(), 3, "one progress update per candidate");
    for (i, update) in updates.iter().enumerate() {
        assert_eq!(update.scanner_id, "bac");
        assert_eq!(update.items_completed, i + 1);
        assert_eq!(update.total_items, 3);
        assert!(update.current_item.is_some());
    }
}

/// Tasks 1.3 + 2.1 + 2.2: the scanner registers under its stable id, loads its
/// wordlist from the seeded reference-data store (deduped, leading-slash
/// normalized), and runs end-to-end through the orchestrator.
#[tokio::test]
async fn registered_scanner_loads_seeded_wordlist_and_runs_via_orchestrator() {
    let dir = tempfile::tempdir().unwrap();
    let db = DatabaseManager::connect(dir.path().join("abyssum.db"))
        .await
        .unwrap();
    let store = db.reference_store();

    // The store-backed scanner's candidate set is normalized, deduped, and non-empty.
    let store_scanner = BacScanner::new(store.clone());
    let candidates = store_scanner.candidate_paths().await.unwrap();
    assert!(
        !candidates.is_empty(),
        "seeded bac_paths should yield candidates"
    );
    assert!(
        candidates.iter().all(|p| p.starts_with('/')),
        "every candidate is leading-slash normalized"
    );
    let unique: std::collections::HashSet<&String> = candidates.iter().collect();
    assert_eq!(unique.len(), candidates.len(), "candidates are deduped");
    assert!(
        candidates.contains(&"/admin".to_string()),
        "bac_paths contributes /admin"
    );

    // A target serving one seeded admin path with sensitive content is flagged
    // end-to-end.
    let mut routes = HashMap::new();
    routes.insert(
        "/admin".to_string(),
        Route::json(r#"{"db_password":"hunter2"}"#),
    );
    let mock = start_mock(routes, Route::not_found("not found"), None).await;

    // Zero the pacing floor so the full seeded wordlist runs quickly over localhost.
    let mut config = Config::default();
    config.scanning.min_delay = 0.0;
    config.scanning.max_delay = 0.0;
    let config = Arc::new(config);

    let mut registry = ScannerRegistry::new(config.clone());
    register_builtins(&mut registry, &store);
    assert!(registry.contains(BacScanner::ID));
    assert!(registry.available().contains(&BacScanner::ID.to_string()));
    let scanner = registry.create("bac").unwrap();
    assert_eq!(scanner.id(), "bac");

    let orchestrator = Orchestrator::new(config, registry);
    let session = orchestrator
        .run_session(vec![mock.target()], vec![BacScanner::ID.to_string()], None)
        .await
        .unwrap();

    assert_eq!(session.status, SessionStatus::Completed);
    let admin = session
        .findings
        .iter()
        .find(|f| {
            f.evidence
                .as_ref()
                .map(|e| e["endpoint"] == "/admin")
                .unwrap_or(false)
        })
        .expect("the seeded /admin endpoint should be flagged as exposed");
    assert_eq!(admin.status, Status::Vulnerable);
    assert_eq!(admin.severity, Severity::Critical);
}
