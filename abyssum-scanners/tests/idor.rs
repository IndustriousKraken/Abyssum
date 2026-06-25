//! Integration tests for the Insecure Direct Object Reference (IDOR) scanner.
//!
//! Every test runs against a hand-rolled, in-process mock HTTP server bound to a
//! random localhost port — **no real targets, no external deps**. The mock maps
//! exact request *targets* (path **and** query string, so parameter enumeration is
//! distinguishable) to canned responses, records each request's target, arrival
//! instant, and whether it carried an `Authorization` / `Cookie` header (so the
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
use abyssum_scanners::{register_builtins, IdorScanner};

// --- Mock HTTP server -------------------------------------------------------

/// A canned response for a request target (or the catch-all default).
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

/// One recorded request: its target (path+query), the instant it arrived, and
/// whether it carried authorization / cookie credentials.
struct Hit {
    target: String,
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

    /// Count recorded hits whose target equals `target`.
    fn count(&self, target: &str) -> usize {
        self.hits
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.target == target)
            .count()
    }
}

/// Start a mock server on a random localhost port. `routes` maps exact request
/// targets (path, optionally with `?query`) to responses; unknown targets get
/// `default`. If `cancel_after` is set, the server fires the token once it has
/// received that many requests (before responding), so a scanner observes
/// cancellation on its next loop check.
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
    let request_target = request_target(&head);
    let had_authorization = header_in(&head, "authorization").is_some();
    let had_cookie = header_in(&head, "cookie").is_some();

    let count = {
        let mut log = hits.lock().unwrap();
        log.push(Hit {
            target: request_target.clone(),
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

    let route = routes.get(&request_target).cloned().unwrap_or(default);
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

/// Recover the full request target (path **and** query string) from a raw request
/// head, so parameter enumeration (`?id=2`) is distinguishable from the baseline.
fn request_target(head: &str) -> String {
    let first_line = head.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let _method = parts.next();
    parts.next().unwrap_or("/").to_string()
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

/// Task 5.2 + spec: harvest a non-default identifier, then enumerate. Some
/// references return distinct unauthorized data (vulnerable), one echoes the
/// caller's own object (safe), one returns a generic not-found shell (safe), and one
/// is absent (404). Exactly the vulnerable reference is reported, with correct
/// evidence and severity.
#[tokio::test]
async fn harvests_baseline_then_reports_only_the_vulnerable_reference() {
    let mut routes = HashMap::new();
    // Harvest: /api/me exposes the caller's own numeric id (42), proving the
    // baseline is harvested rather than the default "1".
    routes.insert(
        "/api/me".to_string(),
        Route::json(r#"{"id":42,"username":"me"}"#),
    );
    // Baseline reference 42: the caller's own object.
    let own = r#"{"id":42,"username":"me","email":"me@example.com","role":"user"}"#;
    routes.insert("/api/users/42".to_string(), Route::json(own));
    // 43: a different user's record exposing credentials → vulnerable, critical.
    routes.insert(
        "/api/users/43".to_string(),
        Route::json(r#"{"id":43,"username":"bob","email":"bob@example.com","password":"s3cret"}"#),
    );
    // 41: echoes the caller's own object verbatim → safe (identical to baseline).
    routes.insert("/api/users/41".to_string(), Route::json(own));
    // 44: a generic not-found shell served with a 200 → safe (error page).
    routes.insert(
        "/api/users/44".to_string(),
        Route::json(r#"{"error":"resource not found"}"#),
    );
    // 45 is absent (404 default).
    let mock = start_mock(routes, Route::not_found("not found"), None).await;

    let scanner = IdorScanner::builder()
        .self_endpoints(["/api/me"])
        .path_templates(["/api/users/{id}"])
        .build();
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
        "exactly the one vulnerable reference is reported: {findings:#?}"
    );
    let finding = &findings[0];
    assert_eq!(finding.scanner_id, "idor");
    assert_eq!(finding.status, Status::Vulnerable);
    assert_eq!(finding.severity, Severity::Critical);

    let evidence = finding.evidence.as_ref().unwrap();
    assert_eq!(evidence["reference_tried"], "43");
    // Proves the baseline was harvested (42), not the default fallback (1).
    assert_eq!(evidence["baseline_reference"], "42");
    assert_eq!(evidence["endpoint"], "/api/users/43");
    assert_eq!(evidence["status"], 200);
    assert_eq!(evidence["data_class"], "credentials");
    assert!(evidence["sensitive_fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f == "password"));
    assert!(evidence["response_sample"]
        .as_str()
        .unwrap()
        .contains("bob"));
}

/// Task 5.3 + spec "Identical response is not a finding": a non-baseline reference
/// that returns a body identical to the baseline is not reported.
#[tokio::test]
async fn identical_to_baseline_is_not_a_finding() {
    let same = r#"{"id":1,"username":"alice","email":"alice@example.com"}"#;
    let mut routes = HashMap::new();
    // Baseline (default "1") and every neighbour return the very same body.
    routes.insert("/api/users/1".to_string(), Route::json(same));
    routes.insert("/api/users/2".to_string(), Route::json(same));
    routes.insert("/api/users/3".to_string(), Route::json(same));
    routes.insert("/api/users/4".to_string(), Route::json(same));
    let mock = start_mock(routes, Route::not_found("nf"), None).await;

    let scanner = IdorScanner::builder()
        .path_templates(["/api/users/{id}"])
        .build();
    let findings = scanner
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    assert!(
        findings.is_empty(),
        "an object echoed identically for every reference is not an IDOR: {findings:#?}"
    );
}

/// Task 5.2 (parameter arm) + task 3.4 + spec: query-parameter enumeration flags a
/// `?id=2` that returns a different object than the `?id=1` baseline.
#[tokio::test]
async fn flags_query_parameter_enumeration() {
    let mut routes = HashMap::new();
    // Baseline ?id=1 — the caller's own record.
    routes.insert(
        "/api/user?id=1".to_string(),
        Route::json(r#"{"id":1,"username":"alice","email":"alice@example.com"}"#),
    );
    // ?id=2 — a different user → vulnerable (PII → high).
    routes.insert(
        "/api/user?id=2".to_string(),
        Route::json(r#"{"id":2,"username":"bob","email":"bob@example.com"}"#),
    );
    // ?id=3 echoes the caller's own object (safe); ?id=4 is a 404 default.
    routes.insert(
        "/api/user?id=3".to_string(),
        Route::json(r#"{"id":1,"username":"alice","email":"alice@example.com"}"#),
    );
    let mock = start_mock(routes, Route::not_found("nf"), None).await;

    let scanner = IdorScanner::builder()
        .param_endpoints(["/api/user"])
        .param_names(["id"])
        .build();
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
        "exactly the differing ?id=2 reference is reported: {findings:#?}"
    );
    let evidence = findings[0].evidence.as_ref().unwrap();
    assert_eq!(evidence["parameter"], "id");
    assert_eq!(evidence["endpoint"], "/api/user");
    assert_eq!(evidence["reference_tried"], "2");
    assert_eq!(evidence["baseline_reference"], "1");
    assert_eq!(findings[0].severity, Severity::High);
}

/// Task 3.2 + spec "Probes without the caller's authorization": even when the scan
/// context carries a credential, every *enumeration* probe is issued with no
/// `Authorization` and no `Cookie`, while the harvest and baseline probes keep the
/// credential (so the baseline reflects the caller's own authorized view).
#[tokio::test]
async fn enumeration_probes_strip_credentials_baseline_keeps_them() {
    let mut routes = HashMap::new();
    // Harvest only a numeric id, so the enumeration set is exactly the numeric
    // neighbours of 42 and the credential assertions stay unambiguous.
    routes.insert("/api/me".to_string(), Route::json(r#"{"id":42}"#));
    routes.insert(
        "/api/users/42".to_string(),
        Route::json(r#"{"id":42,"username":"me","email":"me@example.com"}"#),
    );
    routes.insert(
        "/api/users/43".to_string(),
        Route::json(r#"{"id":43,"username":"bob","email":"bob@example.com"}"#),
    );
    let mock = start_mock(routes, Route::not_found("nf"), None).await;

    let scanner = IdorScanner::builder()
        .self_endpoints(["/api/me"])
        .path_templates(["/api/users/{id}"])
        .build();
    // The context carries BOTH a bearer token and a cookie.
    let ctx = ctx_with(no_pacing(), CancellationToken::new()).with_credential(Credential {
        bearer: Some("super-secret-token".to_string()),
        cookie: Some("session=abc123".to_string()),
    });
    scanner.scan(&mock.target(), &ctx).await.unwrap();

    let hits = mock.hits.lock().unwrap();
    // The harvest (/api/me) and baseline (/api/users/42) keep the credential.
    for kept in ["/api/me", "/api/users/42"] {
        let hit = hits
            .iter()
            .find(|h| h.target == kept)
            .unwrap_or_else(|| panic!("{kept} should have been probed"));
        assert!(
            hit.had_authorization && hit.had_cookie,
            "{kept} (harvest/baseline) must carry the configured credential"
        );
    }
    // Every enumeration probe (the alternative references) strips it.
    let enumerated: Vec<&Hit> = hits
        .iter()
        .filter(|h| h.target.starts_with("/api/users/") && h.target != "/api/users/42")
        .collect();
    assert!(!enumerated.is_empty(), "alternatives were probed");
    assert!(
        enumerated.iter().all(|h| !h.had_authorization),
        "no enumeration probe may carry an Authorization header"
    );
    assert!(
        enumerated.iter().all(|h| !h.had_cookie),
        "no enumeration probe may carry a Cookie header"
    );
}

/// Task 5.4 + spec "Stops promptly on cancellation": cancellation halts further
/// requests and the scan returns the findings gathered so far.
#[tokio::test]
async fn cancellation_stops_promptly_and_returns_partial_results() {
    let cancel = CancellationToken::new();
    let mut routes = HashMap::new();
    // Baseline (default "1") and a vulnerable first neighbour (2).
    routes.insert(
        "/api/users/1".to_string(),
        Route::json(r#"{"id":1,"username":"alice"}"#),
    );
    routes.insert(
        "/api/users/2".to_string(),
        Route::json(r#"{"id":2,"username":"bob","ssn":"123-45-6789"}"#),
    );
    // Cancel once the server has seen 2 requests: the baseline (#1) and the first
    // enumeration probe /api/users/2 (#2).
    let mock = start_mock(routes, Route::not_found("nf"), Some((2, cancel.clone()))).await;

    // No self-endpoints, so the only requests are the baseline + the neighbours of
    // "1" (2, 3, 4) — making the request order deterministic.
    let scanner = IdorScanner::builder()
        .path_templates(["/api/users/{id}"])
        .build();
    let findings = scanner
        .scan(&mock.target(), &ctx_with(no_pacing(), cancel.clone()))
        .await
        .expect("cancellation yields Ok with partial findings, not an error");

    assert_eq!(
        findings.len(),
        1,
        "only reference 2 was probed before cancellation: {findings:#?}"
    );
    assert_eq!(
        findings[0].evidence.as_ref().unwrap()["reference_tried"],
        "2"
    );

    let hits = mock.hits.lock().unwrap();
    assert_eq!(
        hits.len(),
        2,
        "baseline + one enumeration probe; cancellation halted references 3 and 4"
    );
    assert_eq!(hits[0].target, "/api/users/1");
    assert_eq!(hits[1].target, "/api/users/2");
}

/// Task 5.5 + spec "Respects the configured pacing floor": every request after the
/// first (free) one trails its predecessor by at least the floor.
#[tokio::test]
async fn requests_are_paced_through_the_rate_limiter() {
    let mut routes = HashMap::new();
    // A viable baseline so its neighbours (2, 3, 4) are all enumerated.
    routes.insert(
        "/api/users/1".to_string(),
        Route::json(r#"{"id":1,"username":"alice"}"#),
    );
    routes.insert(
        "/api/users/2".to_string(),
        Route::json(r#"{"id":2,"username":"bob"}"#),
    );
    routes.insert(
        "/api/users/3".to_string(),
        Route::json(r#"{"id":3,"username":"carol"}"#),
    );
    routes.insert(
        "/api/users/4".to_string(),
        Route::json(r#"{"id":4,"username":"dave"}"#),
    );
    let mock = start_mock(routes, Route::not_found("nf"), None).await;

    let floor = Duration::from_millis(60);
    // min == max removes base randomness, so each paced gap is exactly the floor.
    let scanner = IdorScanner::builder()
        .path_templates(["/api/users/{id}"])
        .build();
    scanner
        .scan(
            &mock.target(),
            &ctx_with(RateLimiter::new(floor, floor), CancellationToken::new()),
        )
        .await
        .unwrap();

    let hits = mock.hits.lock().unwrap();
    assert_eq!(hits.len(), 4, "baseline + three enumeration probes");
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

/// Task 3.5 + spec "Reports progress": the scanner emits a progress update per
/// enumerated reference (tested / total / current), with the total being the real
/// candidate count established after baseline capture.
#[tokio::test]
async fn emits_progress_per_enumerated_reference() {
    let mut routes = HashMap::new();
    routes.insert(
        "/api/users/1".to_string(),
        Route::json(r#"{"id":1,"username":"alice"}"#),
    );
    let mock = start_mock(routes, Route::not_found("nf"), None).await;

    let updates = Arc::new(Mutex::new(Vec::new()));
    let sink = updates.clone();
    let ctx = ctx_with(no_pacing(), CancellationToken::new())
        .with_progress(Arc::new(move |u| sink.lock().unwrap().push(u)));

    let scanner = IdorScanner::builder()
        .path_templates(["/api/users/{id}"])
        .build();
    scanner.scan(&mock.target(), &ctx).await.unwrap();

    let updates = updates.lock().unwrap();
    // Neighbours of the default baseline "1" are 2, 3, 4 → three references tested.
    assert_eq!(
        updates.len(),
        3,
        "one progress update per enumerated reference"
    );
    for (i, update) in updates.iter().enumerate() {
        assert_eq!(update.scanner_id, "idor");
        assert_eq!(update.items_completed, i + 1);
        assert_eq!(update.total_items, 3);
        assert!(update.current_item.is_some());
    }
}

/// Spec "Error or not-found response is not a finding": an absent template (every
/// reference 404s) yields no findings and no false positives.
#[tokio::test]
async fn absent_endpoint_yields_no_findings() {
    let mock = start_mock(HashMap::new(), Route::not_found("not found"), None).await;
    let scanner = IdorScanner::builder()
        .path_templates(["/api/users/{id}"])
        .param_endpoints(["/api/user"])
        .param_names(["id"])
        .build();
    let findings = scanner
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();
    assert!(
        findings.is_empty(),
        "no viable baseline anywhere → nothing to enumerate: {findings:#?}"
    );
}

/// Tasks 1.3 + 1.2: the scanner registers under its stable id and runs end-to-end
/// through the orchestrator, flagging a vulnerable reference via the target's own
/// `id_template`.
#[tokio::test]
async fn registered_scanner_runs_via_orchestrator() {
    let dir = tempfile::tempdir().unwrap();
    let db = DatabaseManager::connect(dir.path().join("abyssum.db"))
        .await
        .unwrap();
    let store = db.reference_store();

    let mut routes = HashMap::new();
    // Baseline (default "1") and a vulnerable neighbour (2) on the target template.
    routes.insert(
        "/api/orders/1".to_string(),
        Route::json(r#"{"id":1,"buyer":"alice","total":"10.00"}"#),
    );
    routes.insert(
        "/api/orders/2".to_string(),
        Route::json(r#"{"id":2,"buyer":"bob","total":"99.99","credit_card":"4111111111111111"}"#),
    );
    let mock = start_mock(routes, Route::not_found("nf"), None).await;

    // Zero the pacing floor so the scan runs quickly over localhost.
    let mut config = Config::default();
    config.scanning.min_delay = 0.0;
    config.scanning.max_delay = 0.0;
    let config = Arc::new(config);

    let mut registry = ScannerRegistry::new(config.clone());
    register_builtins(&mut registry, &store);
    assert!(registry.contains(IdorScanner::ID));
    assert!(registry.available().contains(&IdorScanner::ID.to_string()));
    let scanner = registry.create("idor").unwrap();
    assert_eq!(scanner.id(), "idor");

    // The target carries its own object-reference template.
    let target = Target::new(
        mock.base.clone(),
        None,
        Some("/api/orders/{id}".to_string()),
    );

    let orchestrator = Orchestrator::new(config, registry);
    let session = orchestrator
        .run_session(vec![target], vec![IdorScanner::ID.to_string()], None)
        .await
        .unwrap();

    assert_eq!(session.status, SessionStatus::Completed);
    let finding = session
        .findings
        .iter()
        .find(|f| {
            f.evidence
                .as_ref()
                .map(|e| e["reference_tried"] == "2")
                .unwrap_or(false)
        })
        .expect("the differing /api/orders/2 reference should be flagged");
    assert_eq!(finding.scanner_id, "idor");
    assert_eq!(finding.status, Status::Vulnerable);
    // The exposed credit-card field raises severity to critical.
    assert_eq!(finding.severity, Severity::Critical);
    // The orchestrator probed at least the baseline plus the template neighbours.
    assert!(mock.count("/api/orders/1") >= 1);
    assert!(mock.count("/api/orders/2") >= 1);
}
