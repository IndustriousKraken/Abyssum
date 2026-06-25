//! Integration tests for the CORS misconfiguration scanner.
//!
//! Every test runs against a hand-rolled, in-process mock HTTP server bound to a
//! random localhost port — **no real targets, no external deps**. The mock echoes
//! the request's `Origin` (and records whether an `Authorization` header arrived)
//! per a configurable [`CorsMode`], logs each request's arrival instant so the
//! pacing test can assert the floor, and can fire a cancellation token after the
//! Nth request so the cancellation test is deterministic. Responses close the
//! connection (`Connection: close`), so each request is one fresh connection the
//! handler serves once.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use url::Url;

use abyssum_core::{
    BaseScanner, Config, Credential, RateLimiter, ScanContext, ScannerRegistry, Severity,
    SingleUserAgent, Status, Target,
};
use abyssum_scanners::CorsScanner;

// --- Mock HTTP server -------------------------------------------------------

/// How the mock answers the cross-origin headers.
#[derive(Clone)]
enum CorsMode {
    /// Reflect the request's `Origin` into `Access-Control-Allow-Origin`,
    /// optionally adding `Access-Control-Allow-Credentials: true`.
    Reflect { credentials: bool },
    /// Return `Access-Control-Allow-Origin: *`, optionally with credentials.
    Wildcard { credentials: bool },
    /// Return a fixed, restricted `Access-Control-Allow-Origin`, with credentials.
    Fixed(String),
    /// Return no CORS headers at all.
    None,
}

/// One recorded request: its `Origin` header, whether it carried an
/// `Authorization` header, and the instant it arrived.
struct Hit {
    origin: Option<String>,
    had_authorization: bool,
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

/// Start a mock CORS server on a random localhost port answering every request
/// per `mode`. If `cancel_after` is set, the server fires the token once it has
/// received that many requests (before responding), so a scanner observes
/// cancellation on its next loop check.
async fn start_mock(mode: CorsMode, cancel_after: Option<(usize, CancellationToken)>) -> Mock {
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
            let mode = mode.clone();
            let hits = hits_bg.clone();
            let cancel_after = cancel_after.clone();
            tokio::spawn(async move {
                handle_conn(sock, mode, hits, cancel_after).await;
            });
        }
    });

    Mock { base, hits }
}

async fn handle_conn(
    mut sock: TcpStream,
    mode: CorsMode,
    hits: Arc<Mutex<Vec<Hit>>>,
    cancel_after: Option<(usize, CancellationToken)>,
) {
    let request = match read_request_head(&mut sock).await {
        Some(head) => head,
        None => return,
    };
    let origin = header_in(&request, "origin");
    let had_authorization = header_in(&request, "authorization").is_some();

    let count = {
        let mut log = hits.lock().unwrap();
        log.push(Hit {
            origin: origin.clone(),
            had_authorization,
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

    // Build the configured CORS headers.
    let mut headers = String::new();
    match &mode {
        CorsMode::Reflect { credentials } => {
            if let Some(origin) = &origin {
                headers.push_str(&format!("Access-Control-Allow-Origin: {origin}\r\n"));
                if *credentials {
                    headers.push_str("Access-Control-Allow-Credentials: true\r\n");
                }
            }
        }
        CorsMode::Wildcard { credentials } => {
            headers.push_str("Access-Control-Allow-Origin: *\r\n");
            if *credentials {
                headers.push_str("Access-Control-Allow-Credentials: true\r\n");
            }
        }
        CorsMode::Fixed(value) => {
            headers.push_str(&format!("Access-Control-Allow-Origin: {value}\r\n"));
            headers.push_str("Access-Control-Allow-Credentials: true\r\n");
        }
        CorsMode::None => {}
    }

    let body = "ok";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}Connection: close\r\n\r\n{}",
        body.len(),
        headers,
        body,
    );
    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.flush().await;
    let _ = sock.shutdown().await;
}

/// Read the request head (up to the blank-line terminator) as text. GET carries
/// no body, so the header terminator is sufficient.
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

/// Extract a header value (case-insensitive name) from a raw request head.
fn header_in(request: &str, name: &str) -> Option<String> {
    for line in request.lines().skip(1) {
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

/// Task 5.2 + spec "Reflected arbitrary origin" / "Credentialed reflection is high
/// severity": a server reflecting every Origin with credentials yields a finding
/// per crafted origin, all High and Vulnerable, with full evidence.
#[tokio::test]
async fn reflects_origin_with_credentials_reports_high_severity_findings() {
    let mock = start_mock(CorsMode::Reflect { credentials: true }, None).await;
    let scanner = CorsScanner::new();
    let findings = scanner
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    // Five crafted origins, each reflected -> five findings.
    assert_eq!(
        findings.len(),
        5,
        "every reflected crafted origin is a finding: {findings:#?}"
    );
    assert!(findings.iter().all(|f| f.severity == Severity::High));
    assert!(findings.iter().all(|f| f.status == Status::Vulnerable));
    assert!(findings.iter().all(|f| f.scanner_id == "cors"));

    // The arbitrary-origin finding carries reproduction evidence.
    let arbitrary = findings
        .iter()
        .find(|f| {
            f.evidence
                .as_ref()
                .map(|e| e["origin_class"] == "arbitrary")
                .unwrap_or(false)
        })
        .expect("an arbitrary-origin finding is reported");
    let evidence = arbitrary.evidence.as_ref().unwrap();
    assert_eq!(evidence["misconfiguration"], "reflected_origin");
    assert_eq!(evidence["credentials_allowed"], true);
    assert_eq!(evidence["access_control_allow_credentials"], "true");
    let acao = evidence["access_control_allow_origin"].as_str().unwrap();
    assert_eq!(
        acao, evidence["origin_sent"],
        "ACAO reflects exactly the origin we sent"
    );
    assert!(evidence["probed_url"]
        .as_str()
        .unwrap()
        .starts_with("http://127.0.0.1"));

    // The null probe is classified as a null-origin acceptance, not a reflection.
    let null = findings
        .iter()
        .find(|f| {
            f.evidence
                .as_ref()
                .map(|e| e["origin_class"] == "null")
                .unwrap_or(false)
        })
        .expect("a null-origin finding is reported");
    assert_eq!(
        null.evidence.as_ref().unwrap()["misconfiguration"],
        "null_origin_accepted"
    );
}

/// Spec "Severity Reflects Exploitability": the same reflection without
/// credentials drops to Medium.
#[tokio::test]
async fn reflects_origin_without_credentials_reports_medium_severity() {
    let mock = start_mock(CorsMode::Reflect { credentials: false }, None).await;
    let scanner = CorsScanner::new();
    let findings = scanner
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    assert_eq!(findings.len(), 5);
    assert!(
        findings.iter().all(|f| f.severity == Severity::Medium),
        "uncredentialed reflections are Medium: {findings:#?}"
    );
    assert!(findings
        .iter()
        .all(|f| f.evidence.as_ref().unwrap()["credentials_allowed"] == false));
}

/// Spec "Wildcard combined with credentials": `ACAO: *` + `ACAC: true` is a High
/// wildcard-with-credentials finding.
#[tokio::test]
async fn wildcard_with_credentials_is_high() {
    let mock = start_mock(CorsMode::Wildcard { credentials: true }, None).await;
    let scanner = CorsScanner::new();
    let findings = scanner
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    // Every probe sees `ACAO: *`, so every probe is a finding.
    assert_eq!(findings.len(), 5);
    assert!(findings.iter().all(|f| f.severity == Severity::High));
    assert!(findings.iter().all(|f| {
        f.evidence.as_ref().unwrap()["misconfiguration"] == "wildcard_with_credentials"
    }));
}

/// Spec "Bare wildcard without credentials": `ACAO: *` without credentials is a
/// Low bare-wildcard finding.
#[tokio::test]
async fn bare_wildcard_is_low() {
    let mock = start_mock(CorsMode::Wildcard { credentials: false }, None).await;
    let scanner = CorsScanner::new();
    let findings = scanner
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    assert_eq!(findings.len(), 5);
    assert!(findings.iter().all(|f| f.severity == Severity::Low));
    assert!(findings
        .iter()
        .all(|f| f.evidence.as_ref().unwrap()["misconfiguration"] == "bare_wildcard"));
}

/// Task 5.3 + spec "Properly restricted origin is not a finding": a server that
/// returns a fixed, unrelated allowed origin yields no findings.
#[tokio::test]
async fn fixed_safe_origin_yields_no_finding() {
    let mock = start_mock(
        CorsMode::Fixed("https://app.trusted.example".to_string()),
        None,
    )
    .await;
    let scanner = CorsScanner::new();
    let findings = scanner
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    assert!(
        findings.is_empty(),
        "a fixed, restricted ACAO is sound: {findings:#?}"
    );
}

/// Spec "No cross-origin allowance is not a finding": a server with no CORS
/// headers yields no findings.
#[tokio::test]
async fn missing_acao_yields_no_finding() {
    let mock = start_mock(CorsMode::None, None).await;
    let scanner = CorsScanner::new();
    let findings = scanner
        .scan(
            &mock.target(),
            &ctx_with(no_pacing(), CancellationToken::new()),
        )
        .await
        .unwrap();

    assert!(findings.is_empty(), "no ACAO -> no finding: {findings:#?}");
}

/// Task 3.2 + spec "Includes credentials when available": when the scan context
/// carries a credential, every probe carries it (the engine attaches it).
#[tokio::test]
async fn attaches_context_credential_to_every_probe() {
    let mock = start_mock(CorsMode::Reflect { credentials: true }, None).await;
    let scanner = CorsScanner::new();
    let ctx = ctx_with(no_pacing(), CancellationToken::new())
        .with_credential(Credential::bearer("secret-token"));
    scanner.scan(&mock.target(), &ctx).await.unwrap();

    let hits = mock.hits.lock().unwrap();
    assert_eq!(hits.len(), 5, "one probe per crafted origin");
    assert!(
        hits.iter().all(|h| h.had_authorization),
        "every probe must carry the context credential"
    );
    // Each probe set its own crafted Origin header — including the null origin.
    assert!(
        hits.iter().all(|h| h.origin.is_some()),
        "every probe must carry an Origin header"
    );
    let origins: Vec<&str> = hits.iter().filter_map(|h| h.origin.as_deref()).collect();
    assert!(origins.contains(&"null"), "the null origin was probed");
    assert!(
        origins.iter().any(|o| o.starts_with("https://")),
        "an attacker https origin was probed"
    );
}

/// Task 5.4 + spec "Stops promptly on cancellation": cancellation halts further
/// requests and the scan returns the findings gathered so far.
#[tokio::test]
async fn cancellation_stops_promptly_and_returns_partial_results() {
    let cancel = CancellationToken::new();
    // Cancel once the server has seen 2 requests (the first two crafted origins).
    let mock = start_mock(
        CorsMode::Reflect { credentials: true },
        Some((2, cancel.clone())),
    )
    .await;

    let scanner = CorsScanner::new();
    let findings = scanner
        .scan(&mock.target(), &ctx_with(no_pacing(), cancel.clone()))
        .await
        .expect("cancellation yields Ok with partial findings, not an error");

    let hits = mock.hits.lock().unwrap();
    assert_eq!(
        hits.len(),
        2,
        "only two origins were probed before cancellation halted the rest"
    );
    assert!(
        findings.len() <= 2,
        "no more findings than origins probed: {findings:#?}"
    );
    assert!(
        !findings.is_empty(),
        "the probes that completed before cancellation still produced findings"
    );
}

/// Task 5.5 + spec "Respects the configured pacing floor": every request after the
/// first (free) one trails its predecessor by at least the floor.
#[tokio::test]
async fn requests_are_paced_through_the_rate_limiter() {
    let mock = start_mock(CorsMode::None, None).await;
    let floor = Duration::from_millis(60);
    // min == max removes base randomness, so each paced gap is exactly the floor.
    let scanner = CorsScanner::new();
    scanner
        .scan(
            &mock.target(),
            &ctx_with(RateLimiter::new(floor, floor), CancellationToken::new()),
        )
        .await
        .unwrap();

    let hits = mock.hits.lock().unwrap();
    assert_eq!(hits.len(), 5, "five crafted origins, no baseline probe");
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

/// Task 3.4 + spec "Reports progress": the scanner emits a progress update per
/// crafted origin (tested / total / current origin).
#[tokio::test]
async fn emits_progress_per_origin() {
    let mock = start_mock(CorsMode::None, None).await;
    let updates = Arc::new(Mutex::new(Vec::new()));
    let sink = updates.clone();
    let ctx = ctx_with(no_pacing(), CancellationToken::new())
        .with_progress(Arc::new(move |u| sink.lock().unwrap().push(u)));

    let scanner = CorsScanner::new();
    scanner.scan(&mock.target(), &ctx).await.unwrap();

    let updates = updates.lock().unwrap();
    assert_eq!(updates.len(), 5, "one progress update per crafted origin");
    for (i, update) in updates.iter().enumerate() {
        assert_eq!(update.scanner_id, "cors");
        assert_eq!(update.items_completed, i + 1);
        assert_eq!(update.total_items, 5);
        assert!(update.current_item.is_some());
    }
}

/// Task 1.3 + spec "Selectable by id": the scanner registers under `cors` and is
/// created by that id.
#[tokio::test]
async fn registered_and_selectable_by_id() {
    let config = Arc::new(Config::default());
    let mut registry = ScannerRegistry::new(config);
    abyssum_scanners::cors::register(&mut registry);

    assert!(registry.contains(CorsScanner::ID));
    assert!(registry.available().contains(&"cors".to_string()));
    let scanner = registry.create("cors").unwrap();
    assert_eq!(scanner.id(), "cors");
}
