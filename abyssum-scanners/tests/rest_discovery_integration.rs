//! Integration tests for the REST discovery scanner.
//!
//! These exercise the whole scanner against a local, deterministic mock HTTP
//! server — **no real targets** (per the change's design). A tiny hand-rolled
//! loopback server (just `tokio::net`, no extra dependency) serves a known set of
//! endpoints and records every request's arrival time, which lets the tests
//! assert exact findings, prompt cancellation with partial results, and that
//! requests are paced through the shared rate limiter.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use abyssum_core::{
    BaseScanner, Config, DatabaseManager, ProgressCallback, RateLimiter, ScanContext, Severity,
    SingleUserAgent, Status, Target,
};
use abyssum_scanners::{RestDiscoveryScanner, StaticWordlistProvider};

// --- The local mock HTTP server ------------------------------------------------

/// A canned response for a path.
#[derive(Clone)]
struct MockResponse {
    status: u16,
    content_type: String,
    body: String,
}

impl MockResponse {
    fn new(status: u16, content_type: &str, body: &str) -> Self {
        Self {
            status,
            content_type: content_type.to_string(),
            body: body.to_string(),
        }
    }
}

/// A minimal loopback HTTP/1.1 server: one request per connection (it answers with
/// `Connection: close`), routing by exact path and recording each request's path
/// and arrival instant for the assertions.
struct MockServer {
    addr: SocketAddr,
    arrivals: Arc<Mutex<Vec<Instant>>>,
    paths: Arc<Mutex<Vec<String>>>,
    _task: tokio::task::JoinHandle<()>,
}

impl MockServer {
    async fn start(routes: HashMap<String, MockResponse>, default: MockResponse) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let arrivals = Arc::new(Mutex::new(Vec::new()));
        let paths = Arc::new(Mutex::new(Vec::new()));
        let arrivals_task = arrivals.clone();
        let paths_task = paths.clone();

        let task = tokio::spawn(async move {
            loop {
                let mut socket = match listener.accept().await {
                    Ok((socket, _)) => socket,
                    Err(_) => break,
                };

                // Read the request head, up to the blank line that terminates it.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match socket.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }

                arrivals_task.lock().unwrap().push(Instant::now());
                let head = String::from_utf8_lossy(&buf);
                let path = request_path(&head);
                paths_task.lock().unwrap().push(path.clone());

                let response = routes
                    .get(&path)
                    .cloned()
                    .unwrap_or_else(|| default.clone());
                let payload = format!(
                    "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response.status,
                    reason_phrase(response.status),
                    response.content_type,
                    response.body.len(),
                    response.body,
                );
                let _ = socket.write_all(payload.as_bytes()).await;
                let _ = socket.flush().await;
                // Drop closes the connection.
            }
        });

        Self {
            addr,
            arrivals,
            paths,
            _task: task,
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

/// Extract the request-line path (without any query string).
fn request_path(head: &str) -> String {
    head.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .map(|raw| raw.split('?').next().unwrap_or(raw).to_string())
        .unwrap_or_else(|| "/".to_string())
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

// --- Helpers -------------------------------------------------------------------

fn context(rate: RateLimiter, cancel: CancellationToken) -> ScanContext {
    ScanContext::new(
        Arc::new(Config::default()),
        rate,
        Arc::new(SingleUserAgent::default()),
        cancel,
    )
}

fn scanner_for(endpoints: &[&str]) -> RestDiscoveryScanner {
    let provider = StaticWordlistProvider::new().with_list(
        "rest_endpoints",
        endpoints.iter().map(|e| e.to_string()).collect(),
    );
    RestDiscoveryScanner::new(Arc::new(provider))
}

// --- Task 5.2: exact findings against known endpoints --------------------------

#[tokio::test]
async fn discovers_exactly_the_known_endpoints() {
    let mut routes = HashMap::new();
    routes.insert(
        "/health".to_string(),
        MockResponse::new(200, "application/json", r#"{"status":"ok"}"#),
    );
    routes.insert(
        "/api/users".to_string(),
        MockResponse::new(200, "application/json", r#"[{"id":1},{"id":2}]"#),
    );
    routes.insert(
        "/secret".to_string(),
        MockResponse::new(401, "text/plain", "unauthorized"),
    );
    // "/ghost" is not routed → the default not-found, matching the baseline.
    let default = MockResponse::new(404, "text/plain", "Not Found");
    let server = MockServer::start(routes, default).await;

    let scanner = scanner_for(&["health", "api/users", "secret", "ghost"]);
    let target = Target::parse(&server.base_url()).unwrap();
    let ctx = context(
        RateLimiter::new(Duration::ZERO, Duration::ZERO),
        CancellationToken::new(),
    );

    let findings = scanner.scan(&target, &ctx).await.unwrap();

    // Three real endpoints discovered; the 404 path yields no finding.
    assert_eq!(findings.len(), 3, "findings: {findings:#?}");

    let find = |needle: &str| {
        findings
            .iter()
            .find(|f| f.title.contains(needle))
            .unwrap_or_else(|| panic!("no finding for {needle}"))
    };

    let health = find("/health");
    assert_eq!(health.status, Status::Info);
    assert_eq!(health.severity, Severity::Info);
    assert!(health.title.contains("Accessible"));
    let evidence = health.evidence.as_ref().unwrap();
    assert_eq!(evidence["status"], 200);
    assert_eq!(evidence["classification"], "accessible");
    assert_eq!(evidence["path"], "/health");

    let users = find("/api/users");
    assert_eq!(users.status, Status::Info);
    assert!(users.title.contains("Accessible"));

    let secret = find("/secret");
    assert_eq!(secret.status, Status::Safe);
    assert_eq!(secret.severity, Severity::Info);
    assert!(secret.title.contains("Protected"));

    assert!(
        !findings.iter().any(|f| f.title.contains("/ghost")),
        "a not-found path must not be reported"
    );

    // Every finding carries this scanner's id.
    assert!(findings.iter().all(|f| f.scanner_id == "rest_discovery"));
}

#[tokio::test]
async fn soft_404_target_yields_no_findings() {
    // A catch-all server: every path (including the baseline probe) returns the
    // same 200 + not-found body. Nothing is distinguishable from absent.
    let routes = HashMap::new();
    let default = MockResponse::new(200, "text/html", "<html><body>Not Found</body></html>");
    let server = MockServer::start(routes, default).await;

    let scanner = scanner_for(&["health", "users", "admin", "api/orders"]);
    let target = Target::parse(&server.base_url()).unwrap();
    let ctx = context(
        RateLimiter::new(Duration::ZERO, Duration::ZERO),
        CancellationToken::new(),
    );

    let findings = scanner.scan(&target, &ctx).await.unwrap();
    assert!(
        findings.is_empty(),
        "soft-404 catch-all must produce no findings, got {findings:#?}"
    );
}

// --- Task 5.3: cancellation stops promptly and yields partial results ----------

#[tokio::test]
async fn cancellation_stops_promptly_with_partial_results() {
    // Each candidate is a distinct accessible endpoint, so without cancellation
    // all four would be findings.
    let mut routes = HashMap::new();
    for name in ["a", "b", "c", "d"] {
        routes.insert(
            format!("/{name}"),
            MockResponse::new(
                200,
                "application/json",
                &format!(r#"{{"endpoint":"{name}"}}"#),
            ),
        );
    }
    let default = MockResponse::new(404, "text/plain", "Not Found");
    let server = MockServer::start(routes, default).await;

    // Cancel from the progress callback after the first candidate is reported.
    let token = CancellationToken::new();
    let cb_token = token.clone();
    let counter = Arc::new(AtomicUsize::new(0));
    let cb_counter = counter.clone();
    let progress: ProgressCallback = Arc::new(move |_update| {
        if cb_counter.fetch_add(1, Ordering::SeqCst) == 0 {
            cb_token.cancel();
        }
    });

    let ctx = context(
        RateLimiter::new(Duration::ZERO, Duration::ZERO),
        token.clone(),
    )
    .with_progress(progress);

    let scanner = scanner_for(&["a", "b", "c", "d"]);
    let target = Target::parse(&server.base_url()).unwrap();

    let findings = scanner.scan(&target, &ctx).await.unwrap();

    // Only the first candidate was probed before cancellation took effect.
    assert_eq!(
        findings.len(),
        1,
        "expected a single partial finding, got {findings:#?}"
    );
    assert!(findings[0].title.contains("/a"));

    // The scan stopped early: not all candidates were requested (baseline + at
    // most one candidate, never all four).
    let requested = server.paths.lock().unwrap().len();
    assert!(
        requested < 1 + 4,
        "cancellation should stop issuing requests promptly, issued {requested}"
    );
}

// --- Task 5.4: requests are paced through the rate limiter ---------------------

#[tokio::test]
async fn requests_are_paced_through_the_rate_limiter() {
    let mut routes = HashMap::new();
    for name in ["one", "two", "three"] {
        routes.insert(
            format!("/{name}"),
            MockResponse::new(200, "application/json", &format!(r#"{{"e":"{name}"}}"#)),
        );
    }
    let default = MockResponse::new(404, "text/plain", "Not Found");
    let server = MockServer::start(routes, default).await;

    // A degenerate band (min == max) makes the paced delay exactly the floor.
    let min_delay = Duration::from_millis(120);
    let ctx = context(
        RateLimiter::new(min_delay, min_delay),
        CancellationToken::new(),
    );

    let scanner = scanner_for(&["one", "two", "three"]);
    let target = Target::parse(&server.base_url()).unwrap();

    scanner.scan(&target, &ctx).await.unwrap();

    let arrivals = server.arrivals.lock().unwrap().clone();
    // The free baseline probe + three paced candidates.
    assert_eq!(
        arrivals.len(),
        4,
        "expected baseline + 3 candidate requests"
    );

    // No request follows its predecessor (to the same host) before the floor.
    // A small slack absorbs measurement jitter; it stays well above the
    // sub-millisecond spacing an unpaced loop would show.
    let slack = Duration::from_millis(20);
    for pair in arrivals.windows(2) {
        let gap = pair[1].duration_since(pair[0]);
        assert!(
            gap + slack >= min_delay,
            "request issued too soon: gap {gap:?} < floor {min_delay:?}"
        );
    }
}

// --- Task 2.1: candidates load from the seeded reference-data store ------------

#[tokio::test]
async fn loads_candidates_from_the_seeded_store() {
    // Open a real (temp-file) SQLite store, seed it from the bundled assets, and
    // prove the scanner draws its candidates straight from it.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let db = DatabaseManager::open(tmp.path()).await.unwrap();
    let store = abyssum_core::ensure_seeded(&db).await.unwrap();

    let scanner = RestDiscoveryScanner::new(Arc::new(store));
    let candidates = scanner.candidate_paths().await.unwrap();

    assert!(
        !candidates.is_empty(),
        "the seeded store must yield candidates"
    );
    // Representative real entries survive, normalized with a single leading slash.
    assert!(candidates.iter().any(|p| p == "/health"));
    assert!(candidates.iter().any(|p| p == "/users"));
    assert!(candidates.iter().all(|p| p.starts_with('/')));

    // Loaded once, deduped across the two lists.
    let mut sorted = candidates.clone();
    let total = sorted.len();
    sorted.sort();
    sorted.dedup();
    assert_eq!(total, sorted.len(), "candidates must be deduped");
}
