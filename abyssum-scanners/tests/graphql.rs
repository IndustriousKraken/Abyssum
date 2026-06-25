//! Integration tests for the GraphQL scanner.
//!
//! Every test runs against a hand-rolled, in-process mock HTTP server bound to a
//! random localhost port — **no real targets, no external deps**. Unlike the GET-only
//! mocks of the other scanners, this one reads the request **body** (via
//! `Content-Length`) so a handler can dispatch on the GraphQL query that was sent: a
//! detection `{ __typename }`, an introspection query, the deep `DepthProbe`, a
//! batched array, or a sensitive-data query. The mock records each request's method,
//! path, and arrival instant, and can fire a cancellation token after the Nth
//! request so the cancellation test is deterministic. Responses close the connection
//! (`Connection: close`).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

use abyssum_core::{
    BaseScanner, Config, DatabaseManager, Orchestrator, RateLimiter, ScanContext, ScannerRegistry,
    SessionStatus, Severity, SingleUserAgent, Status, Target,
};
use abyssum_scanners::{register_builtins, GraphqlScanner};

// --- Mock HTTP server -------------------------------------------------------

/// A canned response.
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
    fn not_found() -> Self {
        Self::new(404, "text/plain", "Not Found")
    }
}

/// A parsed request a handler dispatches on.
struct Req {
    method: String,
    path: String,
    body: String,
}

/// One recorded request: the method and path it used, and the instant it arrived
/// (so the pacing test can measure inter-request gaps).
struct Hit {
    method: String,
    path: String,
    at: Instant,
}

/// The dispatch function a test supplies: given a request, return its response.
type Handler = Arc<dyn Fn(&Req) -> Route + Send + Sync>;

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

/// Start a mock server on a random localhost port. Each request is dispatched
/// through `handler`. If `cancel_after` is set, the server fires the token once it
/// has received that many requests (before responding), so a scanner observes
/// cancellation on its next loop check.
async fn start_mock(handler: Handler, cancel_after: Option<(usize, CancellationToken)>) -> Mock {
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
            let handler = handler.clone();
            let hits = hits_bg.clone();
            let cancel_after = cancel_after.clone();
            tokio::spawn(async move {
                handle_conn(sock, handler, hits, cancel_after).await;
            });
        }
    });

    Mock { base, hits }
}

async fn handle_conn(
    mut sock: TcpStream,
    handler: Handler,
    hits: Arc<Mutex<Vec<Hit>>>,
    cancel_after: Option<(usize, CancellationToken)>,
) {
    let (head, body) = match read_request(&mut sock).await {
        Some(pair) => pair,
        None => return,
    };
    let method = request_method(&head);
    let path = request_path(&head);

    let count = {
        let mut log = hits.lock().unwrap();
        log.push(Hit {
            method: method.clone(),
            path: path.clone(),
            at: Instant::now(),
        });
        log.len()
    };

    if let Some((n, token)) = &cancel_after {
        if count >= *n {
            token.cancel();
        }
    }

    let req = Req { method, path, body };
    let route = handler(&req);
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

/// Read a full request: the header block, then `Content-Length` body bytes.
async fn read_request(sock: &mut TcpStream) -> Option<(String, String)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    // Read until the header terminator.
    let header_end = loop {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_crlf_crlf(&buf) {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let content_length = content_length(&head);
    let mut body = buf[header_end..].to_vec();
    while body.len() < content_length {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    Some((head, String::from_utf8_lossy(&body).to_string()))
}

/// The index of the first `\r\n\r\n` in `buf`, if any.
fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// The `Content-Length` of a request head, or 0 if absent.
fn content_length(head: &str) -> usize {
    header_in(head, "content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// The request method from a raw request head.
fn request_method(head: &str) -> String {
    head.lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or("GET")
        .to_string()
}

/// The request path (without query string) from a raw request head.
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
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

// --- Response fixtures ------------------------------------------------------

/// A representative introspection response with a small schema (two query fields,
/// two mutation fields, sensitive `User`/`Password`/`AuthToken` types).
const INTROSPECTION_SCHEMA: &str = r#"{
    "data": {
        "__schema": {
            "queryType": { "name": "Query" },
            "mutationType": { "name": "Mutation" },
            "types": [
                { "name": "Query", "kind": "OBJECT",
                  "fields": [ { "name": "users" }, { "name": "me" } ] },
                { "name": "Mutation", "kind": "OBJECT",
                  "fields": [ { "name": "createUser" }, { "name": "login" } ] },
                { "name": "User", "kind": "OBJECT", "fields": [ { "name": "id" } ] },
                { "name": "Password", "kind": "OBJECT", "fields": [] },
                { "name": "AuthToken", "kind": "OBJECT", "fields": [] },
                { "name": "String", "kind": "SCALAR" }
            ]
        }
    }
}"#;

/// Dispatch a POST body against an endpoint that has introspection enabled. GET
/// requests to the GraphQL path are detected via a GraphQL error envelope.
fn graphql_handler_introspection_enabled(req: &Req) -> Route {
    if req.path != "/graphql" {
        return Route::not_found();
    }
    if req.method == "GET" {
        // A bare GET answers with a GraphQL-shaped error (detected).
        return Route::new(
            400,
            "application/json",
            r#"{"errors":[{"message":"Must provide query string"}]}"#,
        );
    }
    dispatch_post(&req.body)
}

/// Dispatch a POST body for an introspection-enabled endpoint.
fn dispatch_post(body: &str) -> Route {
    if body.trim_start().starts_with('[') {
        // A batched array: answer with an equal-length array.
        return Route::json(r#"[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]"#);
    }
    if body.contains("__schema") {
        // The introspection query and the deep DepthProbe both ride `__schema`.
        return Route::json(INTROSPECTION_SCHEMA);
    }
    if body.contains("users") {
        // A sensitive-data query disclosing user records with an e-mail and password.
        return Route::json(
            r#"{"data":{"users":[{"id":1,"email":"alice@example.com","password":"hunter2"}]}}"#,
        );
    }
    if body.contains("__typename") {
        return Route::json(r#"{"data":{"__typename":"Query"}}"#);
    }
    Route::json(r#"{"data":{}}"#)
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

/// A scanner with a single candidate path and a tiny query list: an introspection
/// query and a sensitive "Users" query.
fn test_scanner() -> GraphqlScanner {
    GraphqlScanner::with_lists(
        ["/graphql"],
        [
            (
                "Introspection Query",
                "query IntrospectionQuery { __schema { queryType { name } types { name fields { name } } } }",
            ),
            ("Users Query", "query { users { id email password } }"),
        ],
    )
}

// --- Tests ------------------------------------------------------------------

/// Task 6.4 + spec: against a server that serves GraphQL at `/graphql` with
/// introspection enabled, the scanner detects the endpoint and reports an
/// introspection finding carrying the extracted schema as evidence.
#[tokio::test]
async fn detects_endpoint_and_reports_introspection_with_schema_evidence() {
    let mock = start_mock(Arc::new(graphql_handler_introspection_enabled), None).await;
    let findings = test_scanner()
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    assert!(findings.iter().all(|f| f.scanner_id == "graphql"));

    let introspection = findings
        .iter()
        .find(|f| {
            f.evidence
                .as_ref()
                .map(|e| e["check"] == "introspection")
                .unwrap_or(false)
        })
        .expect("an introspection finding is reported");
    assert_eq!(introspection.status, Status::Vulnerable);
    assert!(
        introspection.severity >= Severity::High,
        "introspection is at least high"
    );

    let evidence = introspection.evidence.as_ref().unwrap();
    assert_eq!(evidence["types_count"], 6);
    assert!(evidence["query_fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f == "users"));
    assert!(evidence["mutation_fields"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f == "login"));
    assert!(evidence["sensitive_types"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t == "Password"));

    // The detected endpoint also exposes batching, unbounded depth, and discloses
    // user data — so the overall (max) severity is critical (the password leak).
    assert!(findings
        .iter()
        .any(|f| f.evidence.as_ref().unwrap()["check"] == "batching"));
    assert!(findings
        .iter()
        .any(|f| f.evidence.as_ref().unwrap()["check"] == "query_depth"));
    let disclosure = findings
        .iter()
        .find(|f| f.evidence.as_ref().unwrap()["check"] == "information_disclosure")
        .expect("the Users query disclosure is reported");
    assert_eq!(
        disclosure.severity,
        Severity::Critical,
        "a password leak is critical"
    );
}

/// Task 6.5 + spec: an endpoint with introspection disabled yields no introspection
/// finding (and, here, no findings at all).
#[tokio::test]
async fn introspection_disabled_yields_no_introspection_finding() {
    // The endpoint is detected (POST `{ __typename }` answers GraphQL) but every
    // schema/data query is refused.
    let handler = |req: &Req| -> Route {
        if req.path != "/graphql" {
            return Route::not_found();
        }
        if req.method == "GET" {
            return Route::not_found();
        }
        if req.body.contains("__typename") && !req.body.trim_start().starts_with('[') {
            // Detection probe succeeds.
            return Route::json(r#"{"data":{"__typename":"Query"}}"#);
        }
        // Introspection, depth, batching, and disclosure all refused.
        Route::json(r#"{"errors":[{"message":"GraphQL introspection is not allowed"}]}"#)
    };
    let mock = start_mock(Arc::new(handler), None).await;

    let findings = test_scanner()
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    assert!(
        !findings
            .iter()
            .any(|f| f.evidence.as_ref().unwrap()["check"] == "introspection"),
        "no introspection finding when introspection is disabled: {findings:#?}"
    );
    assert!(
        findings.is_empty(),
        "a fully-refusing endpoint yields no findings: {findings:#?}"
    );
}

/// Task 6.6 + spec "Stops promptly on cancellation": cancellation halts further
/// requests and the scan returns the findings gathered so far.
#[tokio::test]
async fn cancellation_stops_promptly_and_returns_partial_results() {
    let cancel = CancellationToken::new();
    // Fire cancellation once the server has seen 2 requests: the detection GET (#1)
    // and the introspection POST (#2). The scanner builds the introspection finding,
    // then observes cancellation before the depth check.
    let mock = start_mock(
        Arc::new(graphql_handler_introspection_enabled),
        Some((2, cancel.clone())),
    )
    .await;

    let findings = test_scanner()
        .scan(&mock.target(), &ctx_with(no_pacing(), cancel.clone()))
        .await
        .expect("cancellation yields Ok with partial findings, not an error");

    assert_eq!(
        findings.len(),
        1,
        "only the introspection check completed before cancellation: {findings:#?}"
    );
    assert_eq!(
        findings[0].evidence.as_ref().unwrap()["check"],
        "introspection"
    );

    let hits = mock.hits.lock().unwrap();
    assert_eq!(
        hits.len(),
        2,
        "detection GET + introspection POST; cancellation halted the rest"
    );
    assert_eq!(hits[0].method, "GET");
    assert_eq!(hits[0].path, "/graphql");
    assert_eq!(hits[1].method, "POST");
    assert_eq!(hits[1].path, "/graphql");
}

/// Task 6.7 + spec "Respects the configured pacing floor": every request after the
/// first (free) one trails its predecessor by at least the floor. No endpoint is
/// detected here, so the scan stays in the detection phase (GET + POST per path).
#[tokio::test]
async fn requests_are_paced_through_the_rate_limiter() {
    // Every path 404s, so detection probes each with a GET and a POST and never
    // detects — exercising pure detection-phase pacing.
    let handler = |_req: &Req| -> Route { Route::not_found() };
    let mock = start_mock(Arc::new(handler), None).await;

    let floor = Duration::from_millis(60);
    let scanner =
        GraphqlScanner::with_lists(["/graphql", "/api/graphql"], Vec::<(String, String)>::new());
    scanner
        .scan(
            &mock.target(),
            &ctx_with(RateLimiter::new(floor, floor), CancellationToken::new()),
        )
        .await
        .unwrap();

    let hits = mock.hits.lock().unwrap();
    assert_eq!(hits.len(), 4, "two paths × (GET + POST): {}", hits.len());
    // The first request is free; every later one must trail the previous by at least
    // the floor (small slack for measurement granularity).
    for pair in hits.windows(2) {
        let gap = pair[1].at.duration_since(pair[0].at);
        assert!(
            gap >= floor - Duration::from_millis(10),
            "a request was issued before the pacing floor elapsed: gap {gap:?} < floor {floor:?}"
        );
    }
}

/// Spec "Reports progress": the scanner emits progress updates while detecting and
/// while running the exposure checks.
#[tokio::test]
async fn emits_progress_updates() {
    let mock = start_mock(Arc::new(graphql_handler_introspection_enabled), None).await;
    let updates = Arc::new(Mutex::new(Vec::new()));
    let sink = updates.clone();
    let ctx = ctx_with(no_pacing(), CancellationToken::new())
        .with_progress(Arc::new(move |u| sink.lock().unwrap().push(u)));

    test_scanner().scan(&mock.target(), &ctx).await.unwrap();

    let updates = updates.lock().unwrap();
    assert!(!updates.is_empty(), "progress updates are emitted");
    assert!(updates.iter().all(|u| u.scanner_id == "graphql"));
    // Each update names what it tested out of a total, and the current item.
    assert!(updates
        .iter()
        .all(|u| u.total_items > 0 && u.current_item.is_some()));
}

/// Tasks 1.3 + 2.1 + 2.2: the scanner registers under its stable id, loads its
/// path and query lists from the seeded reference-data store, and runs end-to-end
/// through the orchestrator.
#[tokio::test]
async fn registered_scanner_loads_seeded_lists_and_runs_via_orchestrator() {
    let dir = tempfile::tempdir().unwrap();
    let db = DatabaseManager::connect(dir.path().join("abyssum.db"))
        .await
        .unwrap();
    let store = db.reference_store();

    // The store-backed scanner loads the seeded paths and queries.
    let scanner = GraphqlScanner::new(store.clone());
    let paths = scanner.candidate_paths().await.unwrap();
    assert!(
        paths.contains(&"/graphql".to_string()),
        "seeded graphql_paths contributes /graphql: {paths:?}"
    );
    assert!(
        paths.iter().all(|p| p.starts_with('/')),
        "every candidate path is leading-slash normalized"
    );
    let queries = scanner.candidate_queries().await.unwrap();
    assert!(
        !queries.is_empty(),
        "seeded graphql_queries yields probe queries"
    );
    assert!(
        queries.iter().any(
            |(label, body)| label.to_lowercase().contains("introspection")
                && body.contains("__schema")
        ),
        "the seeded list carries a labeled introspection query"
    );

    // A target serving GraphQL at the seeded `/graphql` path with introspection
    // enabled is flagged end-to-end.
    let mock = start_mock(Arc::new(graphql_handler_introspection_enabled), None).await;

    let mut config = Config::default();
    config.scanning.min_delay = 0.0;
    config.scanning.max_delay = 0.0;
    let config = Arc::new(config);

    let mut registry = ScannerRegistry::new(config.clone());
    register_builtins(&mut registry, &store);
    assert!(registry.contains(GraphqlScanner::ID));
    assert!(registry
        .available()
        .contains(&GraphqlScanner::ID.to_string()));
    let created = registry.create("graphql").unwrap();
    assert_eq!(created.id(), "graphql");

    let orchestrator = Orchestrator::new(config, registry);
    let session = orchestrator
        .run_session(
            vec![mock.target()],
            vec![GraphqlScanner::ID.to_string()],
            None,
        )
        .await
        .unwrap();

    assert_eq!(session.status, SessionStatus::Completed);
    let introspection = session
        .findings
        .iter()
        .find(|f| {
            f.evidence
                .as_ref()
                .map(|e| e["check"] == "introspection")
                .unwrap_or(false)
        })
        .expect("the seeded introspection query flags the exposed endpoint");
    assert_eq!(introspection.status, Status::Vulnerable);
    assert!(introspection.severity >= Severity::High);
}
