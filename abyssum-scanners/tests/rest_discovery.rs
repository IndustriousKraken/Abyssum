//! Integration tests for the REST discovery scanner.
//!
//! Every test runs against a hand-rolled, in-process mock HTTP server bound to a
//! random localhost port — **no real targets, no external deps**. The mock
//! records the path and arrival instant of each request so the pacing test can
//! assert the floor, and can fire a cancellation token after the Nth request so
//! the cancellation test is deterministic. Responses close the connection
//! (`Connection: close`), so each request is one fresh connection the handler
//! serves once.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

use abyssum_core::{
    BaseScanner, Config, DatabaseManager, Orchestrator, RateLimiter, ScanContext, ScannerRegistry,
    SessionStatus, SingleUserAgent, Status, Target,
};
use abyssum_scanners::{register_builtins, RestDiscoveryScanner};

// --- Mock HTTP server -------------------------------------------------------

/// A canned response for a path (or the catch-all default).
#[derive(Clone)]
struct Route {
    status: u16,
    content_type: String,
    body: String,
}

impl Route {
    fn new(status: u16, content_type: &str, body: &str) -> Self {
        Self {
            status,
            content_type: content_type.to_string(),
            body: body.to_string(),
        }
    }
    fn json(body: &str) -> Self {
        Self::new(200, "application/json", body)
    }
    fn not_found(body: &str) -> Self {
        Self::new(404, "text/plain", body)
    }
}

/// One recorded request: its path and the instant it arrived.
struct Hit {
    path: String,
    at: Instant,
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
/// fires the token once it has received that many requests (before responding),
/// so a scanner observes cancellation on its next loop check.
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
    let path = match read_request_path(&mut sock).await {
        Some(path) => path,
        None => return,
    };

    let count = {
        let mut log = hits.lock().unwrap();
        log.push(Hit {
            path: path.clone(),
            at: Instant::now(),
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
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        route.status,
        reason_phrase(route.status),
        route.content_type,
        route.body.len(),
        route.body,
    );
    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.flush().await;
    let _ = sock.shutdown().await;
}

/// Read just enough of the request to recover its path (GET has no body, so the
/// header terminator is sufficient).
async fn read_request_path(sock: &mut TcpStream) -> Option<String> {
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
    let text = String::from_utf8_lossy(&buf);
    let first_line = text.lines().next()?;
    let mut parts = first_line.split_whitespace();
    let _method = parts.next()?;
    let request_target = parts.next()?;
    Some(
        request_target
            .split('?')
            .next()
            .unwrap_or(request_target)
            .to_string(),
    )
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
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

/// Task 5.2 + spec: discovers exactly the served endpoints, classifying an open
/// one as accessible and an auth-gated one as protected; 404s are not reported.
///
/// The protected endpoint answers `401` rather than `403`: the engine's rate
/// limiter (correctly) treats `403`/`429` as a distress signal and backs off, so
/// a `403` here would make the test sleep on real backoff. `401` exercises the
/// same "protected" classification branch without tripping pacing (the classifier
/// treats `401`/`403` identically — see the unit tests).
#[tokio::test]
async fn discovers_and_classifies_known_endpoints() {
    let mut routes = HashMap::new();
    routes.insert(
        "/api/v1/health".to_string(),
        Route::json(r#"{"status":"ok"}"#),
    );
    routes.insert(
        "/admin".to_string(),
        Route::new(401, "application/json", r#"{"error":"unauthorized"}"#),
    );
    let mock = start_mock(routes, Route::not_found("not found"), None).await;

    let scanner = RestDiscoveryScanner::with_paths([
        "/api/v1/health",
        "/admin",
        "/does-not-exist",
        "/also-missing",
    ]);
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
        "exactly the two served endpoints should be reported: {findings:#?}"
    );

    let health = findings
        .iter()
        .find(|f| f.title.contains("/api/v1/health"))
        .expect("accessible endpoint reported");
    assert_eq!(health.status, Status::Info, "accessible -> info");
    let health_evidence = health.evidence.as_ref().unwrap();
    assert_eq!(health_evidence["status"], 200);
    assert_eq!(health_evidence["path"], "/api/v1/health");

    let admin = findings
        .iter()
        .find(|f| f.title.contains("/admin"))
        .expect("protected endpoint reported");
    assert_eq!(admin.status, Status::Safe, "protected -> safe");
    assert_eq!(admin.evidence.as_ref().unwrap()["status"], 401);
}

/// Task 5.2 + spec scenario "Soft-404 is not a finding": a target that answers
/// unknown paths with 200 + a generic body must not produce phantom findings.
#[tokio::test]
async fn soft_404_responses_are_not_reported() {
    let mut routes = HashMap::new();
    routes.insert(
        "/health".to_string(),
        Route::json(r#"{"status":"ok","detail":"healthy"}"#),
    );
    // A soft-404 site: every unknown path returns 200 with the same catch-all body.
    let soft = Route::new(200, "text/html", "<html><body>Page not found</body></html>");
    let mock = start_mock(routes, soft, None).await;

    let scanner = RestDiscoveryScanner::with_paths(["/health", "/ghost-one", "/ghost-two"]);
    let findings = scanner
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    assert_eq!(
        findings.len(),
        1,
        "only the real endpoint; soft-404s must be classified absent: {findings:#?}"
    );
    assert!(findings[0].title.contains("/health"));
}

/// An endpoint that streams an oversized body must not be buffered whole: the
/// scanner caps the body it reads, still classifies by status, and flags the
/// truncation in the finding evidence. The served body (2 MiB) comfortably
/// exceeds the scanner's per-probe cap.
#[tokio::test]
async fn oversized_response_body_is_capped_and_flagged() {
    let mut routes = HashMap::new();
    // text/plain (not a JSON/XML content-type), so api-shaped would otherwise
    // depend on the body parse — which is skipped for a truncated body.
    let big = "A".repeat(2 * 1024 * 1024);
    routes.insert("/big".to_string(), Route::new(200, "text/plain", &big));
    let mock = start_mock(routes, Route::not_found("nf"), None).await;

    let scanner = RestDiscoveryScanner::with_paths(["/big"]);
    let findings = scanner
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    assert_eq!(
        findings.len(),
        1,
        "the oversized endpoint is still discovered by status: {findings:#?}"
    );
    let evidence = findings[0].evidence.as_ref().unwrap();
    assert_eq!(evidence["status"], 200);
    assert_eq!(
        evidence["body_truncated"], true,
        "an oversized body must be flagged truncated"
    );
    let body_length = evidence["body_length"].as_u64().unwrap();
    assert!(
        body_length < big.len() as u64,
        "the buffered body must be capped below the served size: {body_length} vs {}",
        big.len()
    );
    // A truncated text/plain body is not parsed as JSON, so it is not api-shaped.
    assert_eq!(evidence["api_shaped"], false);
}

/// Task 5.3 + spec scenario "Stops promptly on cancellation": cancellation halts
/// further requests and the scan returns the findings gathered so far.
#[tokio::test]
async fn cancellation_stops_promptly_and_returns_partial_results() {
    let cancel = CancellationToken::new();
    let mut routes = HashMap::new();
    routes.insert("/found".to_string(), Route::json(r#"{"ok":true}"#));
    // Cancel once the server has seen 2 requests: the baseline probe (#1) and the
    // first wordlist probe, /found (#2).
    let mock = start_mock(routes, Route::not_found("nf"), Some((2, cancel.clone()))).await;

    let scanner = RestDiscoveryScanner::with_paths(["/found", "/p1", "/p2", "/p3", "/p4", "/p5"]);
    let findings = scanner
        .scan(&mock.target(), &ctx_with(no_pacing(), cancel.clone()))
        .await
        .expect("cancellation yields Ok with partial findings, not an error");

    assert_eq!(
        findings.len(),
        1,
        "only /found was probed before cancellation"
    );
    assert!(findings[0].title.contains("/found"));
    let hits = mock.hits.lock().unwrap();
    assert_eq!(
        hits.len(),
        2,
        "baseline + one probe; cancellation halted the remaining five paths"
    );
    // The second (and last) request was the first wordlist path; the rest never went out.
    assert_eq!(hits[1].path, "/found");
}

/// Task 5.4 + spec scenario "Respects the configured pacing floor": every request
/// after the first (free) one is paced at least the floor behind its predecessor.
#[tokio::test]
async fn requests_are_paced_through_the_rate_limiter() {
    let mock = start_mock(HashMap::new(), Route::not_found("nf"), None).await;
    let floor = Duration::from_millis(60);
    // min == max removes base randomness, so each paced gap is exactly the floor.
    let scanner = RestDiscoveryScanner::with_paths(["/a", "/b", "/c"]);
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

/// Task 3.3: the scanner emits progress (tested / total / current path).
#[tokio::test]
async fn emits_progress_per_candidate() {
    let mock = start_mock(HashMap::new(), Route::not_found("nf"), None).await;
    let updates = Arc::new(Mutex::new(Vec::new()));
    let sink = updates.clone();
    let ctx = ctx_with(no_pacing(), CancellationToken::new())
        .with_progress(Arc::new(move |u| sink.lock().unwrap().push(u)));

    let scanner = RestDiscoveryScanner::with_paths(["/a", "/b", "/c"]);
    scanner.scan(&mock.target(), &ctx).await.unwrap();

    let updates = updates.lock().unwrap();
    assert_eq!(updates.len(), 3, "one progress update per candidate");
    for (i, update) in updates.iter().enumerate() {
        assert_eq!(update.scanner_id, "rest_discovery");
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

    // The store-backed scanner's candidate set is normalized and deduped, draws
    // from both seeded lists, and is non-empty.
    let store_scanner = RestDiscoveryScanner::new(store.clone());
    let candidates = store_scanner.candidate_paths().await.unwrap();
    assert!(
        !candidates.is_empty(),
        "seeded wordlist should yield candidates"
    );
    assert!(
        candidates.iter().all(|p| p.starts_with('/')),
        "every candidate is leading-slash normalized"
    );
    let unique: std::collections::HashSet<&String> = candidates.iter().collect();
    assert_eq!(unique.len(), candidates.len(), "candidates are deduped");
    assert!(
        candidates.contains(&"/health".to_string()),
        "rest_endpoints contributes /health"
    );
    assert!(
        candidates.contains(&"/api/v1/".to_string()),
        "rest_api_bases contributes /api/v1/"
    );

    // A target serving one of the seeded endpoint names is discovered end-to-end.
    let mut routes = HashMap::new();
    routes.insert("/health".to_string(), Route::json(r#"{"status":"ok"}"#));
    let mock = start_mock(routes, Route::not_found("not found"), None).await;

    // Zero the pacing floor so the full seeded wordlist runs quickly over localhost.
    let mut config = Config::default();
    config.scanning.min_delay = 0.0;
    config.scanning.max_delay = 0.0;
    let config = Arc::new(config);

    let mut registry = ScannerRegistry::new(config.clone());
    register_builtins(&mut registry, &store);
    assert!(registry.contains(RestDiscoveryScanner::ID));
    assert!(registry
        .available()
        .contains(&RestDiscoveryScanner::ID.to_string()));

    let orchestrator = Orchestrator::new(config, registry);
    let session = orchestrator
        .run_session(
            vec![mock.target()],
            vec![RestDiscoveryScanner::ID.to_string()],
            None,
        )
        .await
        .unwrap();

    assert_eq!(session.status, SessionStatus::Completed);
    assert!(
        session.findings.iter().any(|f| f.title.contains("/health")),
        "the seeded /health endpoint should be discovered: {:#?}",
        session.findings
    );
}
