//! Integration tests for the OpenAPI/Swagger discovery scanner.
//!
//! Every test runs against a hand-rolled, in-process mock HTTP server bound to a
//! random localhost port — **no real targets, no external deps**. The mock records
//! the path and arrival instant of each request so the pacing test can assert the
//! floor, and can fire a cancellation token after the Nth request so the
//! cancellation test is deterministic. Responses close the connection
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
use abyssum_scanners::{register_builtins, OpenApiDiscoveryScanner};

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
    /// The origin (scheme://host:port) the scanner anchors documented endpoints to.
    fn origin(&self) -> String {
        self.base.origin().ascii_serialization()
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

/// A minimal but genuine OpenAPI 3.x document documenting two paths.
const OPENAPI_DOC: &str = r#"{"openapi":"3.0.1","info":{"title":"Demo"},"paths":{"/users":{"get":{}},"/users/{id}":{"get":{}}}}"#;

// --- Tests ------------------------------------------------------------------

/// Test 6.3 + spec scenarios "Discovers a published spec document" / "Unrelated
/// successful response is rejected": exactly the spec location is reported, with its
/// documented endpoints; unrelated 2xx JSON and an HTML page at other candidate
/// locations are not.
#[tokio::test]
async fn reports_exactly_the_spec_with_its_endpoints() {
    let mut routes = HashMap::new();
    routes.insert("/openapi.json".to_string(), Route::json(OPENAPI_DOC));
    // Unrelated 2xx JSON (no marker) and an HTML page — both must be rejected.
    routes.insert(
        "/data".to_string(),
        Route::json(r#"{"items":[1,2,3],"page":1}"#),
    );
    routes.insert(
        "/docs".to_string(),
        Route::new(200, "text/html", "<html><body>API docs</body></html>"),
    );
    let mock = start_mock(routes, Route::not_found("not found"), None).await;

    let scanner = OpenApiDiscoveryScanner::with_paths([
        "/openapi.json",
        "/data",
        "/docs",
        "/swagger.json", // unserved -> 404 -> ignored
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
        1,
        "only the genuine spec location should be reported: {findings:#?}"
    );
    let finding = &findings[0];
    assert_eq!(finding.status, Status::Info);
    assert!(finding.title.contains("/openapi.json"));
    assert!(finding.title.contains("OpenAPI 3.0.1"));

    let evidence = finding.evidence.as_ref().unwrap();
    assert_eq!(evidence["location"], "/openapi.json");
    assert_eq!(evidence["spec_type"], "OpenAPI 3.0.1");
    let endpoints: Vec<String> = evidence["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect();
    let origin = mock.origin();
    assert!(endpoints.contains(&format!("{origin}/users")));
    assert!(endpoints.contains(&format!("{origin}/users/{{id}}")));
    assert_eq!(endpoints.len(), 2);
}

/// Spec scenario "Endpoints de-duplicated across specs": two specs documenting an
/// overlapping path each produce a finding, but the overlap is attributed to only
/// one of them.
#[tokio::test]
async fn overlapping_endpoint_is_attributed_to_at_most_one_finding() {
    let mut routes = HashMap::new();
    // Both specs document /users; each also documents one unique path.
    routes.insert(
        "/openapi.json".to_string(),
        Route::json(r#"{"openapi":"3.0.0","paths":{"/users":{},"/orders":{}}}"#),
    );
    routes.insert(
        "/swagger.json".to_string(),
        Route::json(r#"{"swagger":"2.0","paths":{"/users":{},"/carts":{}}}"#),
    );
    let mock = start_mock(routes, Route::not_found("nf"), None).await;

    let scanner = OpenApiDiscoveryScanner::with_paths(["/openapi.json", "/swagger.json"]);
    let findings = scanner
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    assert_eq!(findings.len(), 2, "both specs are reported: {findings:#?}");

    let origin = mock.origin();
    let users = format!("{origin}/users");
    let appearances = findings
        .iter()
        .filter(|f| {
            f.evidence.as_ref().unwrap()["endpoints"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e == &serde_json::Value::String(users.clone()))
        })
        .count();
    assert_eq!(
        appearances, 1,
        "the overlapping /users endpoint must appear in exactly one finding's evidence"
    );

    // Each unique path still shows up under its own spec.
    let all_endpoints: Vec<String> = findings
        .iter()
        .flat_map(|f| {
            f.evidence.as_ref().unwrap()["endpoints"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e.as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        })
        .collect();
    assert!(all_endpoints.contains(&format!("{origin}/orders")));
    assert!(all_endpoints.contains(&format!("{origin}/carts")));
}

/// Spec scenario "No spec exposed": a target serving no spec at any candidate
/// location produces no findings.
#[tokio::test]
async fn no_spec_exposed_yields_no_findings() {
    // Every candidate 404s; one location serves unrelated 2xx JSON.
    let mut routes = HashMap::new();
    routes.insert("/data".to_string(), Route::json(r#"{"ok":true}"#));
    let mock = start_mock(routes, Route::not_found("nf"), None).await;

    let scanner = OpenApiDiscoveryScanner::with_paths([
        "/openapi.json",
        "/swagger.json",
        "/data",
        "/api-docs",
    ]);
    let findings = scanner
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    assert!(
        findings.is_empty(),
        "no candidate served a spec, so nothing is reported: {findings:#?}"
    );
}

/// Test 6.4 + spec scenario "Stops promptly on cancellation": cancellation halts
/// further requests and the scan returns the findings gathered so far.
#[tokio::test]
async fn cancellation_stops_promptly_and_returns_partial_results() {
    let cancel = CancellationToken::new();
    let mut routes = HashMap::new();
    routes.insert("/openapi.json".to_string(), Route::json(OPENAPI_DOC));
    // Cancel once the server has seen the first request (the spec at /openapi.json).
    // There is no baseline probe, so request #1 is the first candidate.
    let mock = start_mock(routes, Route::not_found("nf"), Some((1, cancel.clone()))).await;

    let scanner = OpenApiDiscoveryScanner::with_paths([
        "/openapi.json",
        "/swagger.json",
        "/api-docs",
        "/spec.yaml",
    ]);
    let findings = scanner
        .scan(&mock.target(), &ctx_with(no_pacing(), cancel.clone()))
        .await
        .expect("cancellation yields Ok with partial findings, not an error");

    assert_eq!(
        findings.len(),
        1,
        "only /openapi.json was probed before cancellation: {findings:#?}"
    );
    assert!(findings[0].title.contains("/openapi.json"));

    let hits = mock.hits.lock().unwrap();
    assert_eq!(
        hits.len(),
        1,
        "cancellation halted the remaining three candidates"
    );
    assert_eq!(hits[0].path, "/openapi.json");
}

/// Test 6.5 + spec scenario "Respects the configured pacing floor": every request
/// after the first (free) one is paced at least the floor behind its predecessor.
#[tokio::test]
async fn requests_are_paced_through_the_rate_limiter() {
    // No specs served (all 404) — we only care about request timing.
    let mock = start_mock(HashMap::new(), Route::not_found("nf"), None).await;
    let floor = Duration::from_millis(60);
    // min == max removes base randomness, so each paced gap is exactly the floor.
    let scanner =
        OpenApiDiscoveryScanner::with_paths(["/openapi.json", "/swagger.json", "/api-docs"]);
    scanner
        .scan(
            &mock.target(),
            &ctx_with(RateLimiter::new(floor, floor), CancellationToken::new()),
        )
        .await
        .unwrap();

    let hits = mock.hits.lock().unwrap();
    assert_eq!(
        hits.len(),
        3,
        "one request per candidate, no baseline probe"
    );
    // First request is free; every later request must trail the previous by at
    // least the floor (small slack for measurement granularity).
    for pair in hits.windows(2) {
        let gap = pair[1].at.duration_since(pair[0].at);
        assert!(
            gap >= floor - Duration::from_millis(10),
            "a request was issued before the pacing floor elapsed: gap {gap:?} < floor {floor:?}"
        );
    }
}

/// Task 3.3: the scanner emits progress (tested / total / current path) once per
/// candidate.
#[tokio::test]
async fn emits_progress_per_candidate() {
    let mock = start_mock(HashMap::new(), Route::not_found("nf"), None).await;
    let updates = Arc::new(Mutex::new(Vec::new()));
    let sink = updates.clone();
    let ctx = ctx_with(no_pacing(), CancellationToken::new())
        .with_progress(Arc::new(move |u| sink.lock().unwrap().push(u)));

    let scanner =
        OpenApiDiscoveryScanner::with_paths(["/openapi.json", "/swagger.json", "/api-docs"]);
    scanner.scan(&mock.target(), &ctx).await.unwrap();

    let updates = updates.lock().unwrap();
    assert_eq!(updates.len(), 3, "one progress update per candidate");
    for (i, update) in updates.iter().enumerate() {
        assert_eq!(update.scanner_id, "openapi_discovery");
        assert_eq!(update.items_completed, i + 1);
        assert_eq!(update.total_items, 3);
        assert!(update.current_item.is_some());
    }
}

/// A YAML spec served at a `.yaml` location is parsed and reported just like JSON.
#[tokio::test]
async fn discovers_a_yaml_spec() {
    let yaml = "openapi: 3.0.0\npaths:\n  /widgets:\n    get: {}\n  /widgets/{id}:\n    get: {}\n";
    let mut routes = HashMap::new();
    routes.insert(
        "/openapi.yaml".to_string(),
        Route::new(200, "application/yaml", yaml),
    );
    let mock = start_mock(routes, Route::not_found("nf"), None).await;

    let scanner = OpenApiDiscoveryScanner::with_paths(["/openapi.yaml"]);
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
        "the YAML spec is discovered: {findings:#?}"
    );
    let evidence = findings[0].evidence.as_ref().unwrap();
    assert_eq!(evidence["spec_type"], "OpenAPI 3.0.0");
    let origin = mock.origin();
    let endpoints: Vec<String> = evidence["endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect();
    assert!(endpoints.contains(&format!("{origin}/widgets")));
    assert!(endpoints.contains(&format!("{origin}/widgets/{{id}}")));
}

/// Tasks 1.3 + 2.1 + 2.2: the scanner registers under its stable id, loads its
/// spec-location wordlist from the seeded reference-data store (deduped,
/// leading-slash normalized), and runs end-to-end through the orchestrator.
#[tokio::test]
async fn registered_scanner_loads_seeded_wordlist_and_runs_via_orchestrator() {
    let dir = tempfile::tempdir().unwrap();
    let db = DatabaseManager::connect(dir.path().join("abyssum.db"))
        .await
        .unwrap();
    let store = db.reference_store();

    // The store-backed scanner's candidate set is normalized, deduped, and non-empty.
    let store_scanner = OpenApiDiscoveryScanner::new(store.clone());
    let candidates = store_scanner.candidate_paths().await.unwrap();
    assert!(
        !candidates.is_empty(),
        "seeded openapi-discovery-paths list should yield candidates"
    );
    assert!(
        candidates.iter().all(|p| p.starts_with('/')),
        "every candidate is leading-slash normalized"
    );
    let unique: std::collections::HashSet<&String> = candidates.iter().collect();
    assert_eq!(unique.len(), candidates.len(), "candidates are deduped");
    assert!(
        candidates.contains(&"/openapi.json".to_string()),
        "the seeded list contributes /openapi.json"
    );

    // A target serving a spec at one of the seeded locations is discovered end-to-end.
    let mut routes = HashMap::new();
    routes.insert("/openapi.json".to_string(), Route::json(OPENAPI_DOC));
    let mock = start_mock(routes, Route::not_found("not found"), None).await;

    // Zero the pacing floor so the full seeded wordlist runs quickly over localhost.
    let mut config = Config::default();
    config.scanning.min_delay = 0.0;
    config.scanning.max_delay = 0.0;
    let config = Arc::new(config);

    let mut registry = ScannerRegistry::new(config.clone());
    register_builtins(&mut registry, &store);
    assert!(registry.contains(OpenApiDiscoveryScanner::ID));
    assert!(registry
        .available()
        .contains(&OpenApiDiscoveryScanner::ID.to_string()));

    let orchestrator = Orchestrator::new(config, registry);
    let session = orchestrator
        .run_session(
            vec![mock.target()],
            vec![OpenApiDiscoveryScanner::ID.to_string()],
            None,
        )
        .await
        .unwrap();

    assert_eq!(session.status, SessionStatus::Completed);
    assert!(
        session
            .findings
            .iter()
            .any(|f| f.title.contains("/openapi.json")),
        "the seeded /openapi.json location should be discovered: {:#?}",
        session.findings
    );
}
