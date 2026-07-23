//! Integration tests for the subdomain-reconnaissance scanner.
//!
//! Every test runs against hand-rolled, in-process mock HTTP servers bound to
//! random localhost ports — **no real network, no external deps, no real DNS**.
//! The passive source is either stubbed with a fixed candidate list
//! ([`SubdomainReconScanner::with_candidates`]) or pointed at a local mock that
//! serves crt.sh-style JSON ([`SubdomainReconScanner::with_source_base`]). A
//! "dead" candidate is a bound-then-dropped port, so a probe to it is refused and
//! the scan classifies the host as not-live without touching the network.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use url::Url;

use abyssum_core::{
    BaseScanner, Config, DatabaseManager, RateLimiter, ScanContext, ScannerRegistry, Severity,
    SingleUserAgent, Status, Target,
};
use abyssum_scanners::{SubdomainReconScanner, register_builtins};

// --- Mock HTTP server -------------------------------------------------------

/// A running mock server: its authority (`127.0.0.1:PORT`) and the request heads
/// it received (request line + headers), for asserting what was queried.
struct Mock {
    authority: String,
    requests: Arc<Mutex<Vec<String>>>,
}

/// Start a mock that answers every request with `status` and `body`, closing the
/// connection each time. Records each request head so tests can assert the path
/// and headers a query carried.
async fn start_mock(status: u16, body: &'static str) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_bg = requests.clone();

    tokio::spawn(async move {
        loop {
            let (sock, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let requests = requests_bg.clone();
            tokio::spawn(async move {
                handle_conn(sock, status, body, requests).await;
            });
        }
    });

    Mock {
        authority,
        requests,
    }
}

async fn handle_conn(
    mut sock: TcpStream,
    status: u16,
    body: &'static str,
    requests: Arc<Mutex<Vec<String>>>,
) {
    if let Some(head) = read_request_head(&mut sock).await {
        requests.lock().unwrap().push(head);
    }
    let reason = if (200..300).contains(&status) {
        "OK"
    } else {
        "Not Found"
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.flush().await;
    let _ = sock.shutdown().await;
}

/// Read the request head (up to the blank-line terminator). GET carries no body,
/// so the header terminator is sufficient.
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

/// Bind a port and immediately drop the listener, yielding an authority nothing
/// listens on: a probe to it is refused, so the candidate is classified dead.
async fn dead_authority() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    drop(listener);
    authority
}

// --- Scan helpers -----------------------------------------------------------

fn ctx() -> ScanContext {
    ctx_with(Config::default())
}

/// A context with active subdomain brute-force turned on (off by default).
fn ctx_bruteforce() -> ScanContext {
    let mut config = Config::default();
    config.scanning.subdomain_bruteforce = true;
    ctx_with(config)
}

fn ctx_with(config: Config) -> ScanContext {
    ScanContext::new(
        Arc::new(config),
        RateLimiter::new(Duration::ZERO, Duration::ZERO),
        Arc::new(SingleUserAgent::default()),
        CancellationToken::new(),
    )
}

/// A DoH JSON body that resolves (NOERROR + an A record) — the name exists.
const DOH_EXISTS: &str = r#"{"Status":0,"Answer":[{"name":"x","type":1,"data":"93.184.216.34"}]}"#;
/// A DoH JSON body for NXDOMAIN — the name does not exist.
const DOH_NXDOMAIN: &str = r#"{"Status":3}"#;

/// An apex target probed over plain HTTP, so probes reach the localhost mocks.
///
/// The apex is `127.0.0.1` (not a public domain) precisely because the mocks bind
/// to `127.0.0.1:PORT`: reconnaissance now only ever probes the apex or a subdomain
/// of it, so a candidate must be within the apex to be probed at all. Each mock's
/// authority (`127.0.0.1:PORT`) shares the apex host, differing only by port, and a
/// different port on the apex host is still in scope.
fn apex() -> Target {
    Target::parse("http://127.0.0.1").unwrap()
}

// --- Tests ------------------------------------------------------------------

/// Task 6 (the required no-network test): given a stubbed passive source and
/// stubbed HTTP responses, a takeover-fingerprinted host yields a takeover
/// finding, a plain live host yields an info finding, and a dead host yields
/// neither.
#[tokio::test]
async fn three_outcomes_takeover_live_and_dead() {
    let takeover = start_mock(
        404,
        "<Error><Code>NoSuchBucket</Code>The specified bucket does not exist</Error>",
    )
    .await;
    let live = start_mock(200, "<html><body>hello from a real service</body></html>").await;
    let dead = dead_authority().await;

    let scanner = SubdomainReconScanner::with_candidates([
        takeover.authority.clone(),
        live.authority.clone(),
        dead.clone(),
    ]);
    let findings = scanner.scan(&apex(), &ctx()).await.unwrap();

    // The dead host produced nothing: exactly two findings, one per live host.
    assert_eq!(
        findings.len(),
        2,
        "takeover + live are reported, dead is not: {findings:#?}"
    );

    let takeover_finding = findings
        .iter()
        .find(|f| f.evidence.as_ref().and_then(|e| e["host"].as_str()) == Some(&takeover.authority))
        .expect("the takeover host is reported");
    assert_eq!(takeover_finding.status, Status::Vulnerable);
    assert!(takeover_finding.severity >= Severity::High);
    assert_eq!(
        takeover_finding.evidence.as_ref().unwrap()["suspected_service"],
        "Amazon S3"
    );
    assert!(takeover_finding.title.contains("Amazon S3"));

    let live_finding = findings
        .iter()
        .find(|f| f.evidence.as_ref().and_then(|e| e["host"].as_str()) == Some(&live.authority))
        .expect("the plain live host is reported");
    assert_eq!(live_finding.status, Status::Info);
    assert_eq!(live_finding.severity, Severity::Info);
    assert_eq!(live_finding.evidence.as_ref().unwrap()["takeover"], false);

    // The dead host is in neither finding.
    assert!(
        !findings
            .iter()
            .any(|f| f.evidence.as_ref().and_then(|e| e["host"].as_str()) == Some(&dead)),
        "the dead host must not be reported"
    );
}

/// Tasks 2 + 3 + spec "Subdomains gathered from a passive source" / "Source
/// queries are paced": the scanner queries a passive source through the paced
/// `send` path, parses the crt.sh-style names it returns, and probes them.
#[tokio::test]
async fn discovers_from_passive_source_then_probes() {
    let live = start_mock(200, "<html>up</html>").await;
    // The source lists the (localhost) live host as a discovered name for the apex.
    let source_json: &'static str = Box::leak(
        format!(
            r#"[{{"name_value":"{}","common_name":"{}"}}]"#,
            live.authority, live.authority
        )
        .into_boxed_str(),
    );
    let source = start_mock(200, source_json).await;

    let scanner = SubdomainReconScanner::with_source_base(
        Url::parse(&format!("http://{}/", source.authority)).unwrap(),
    );
    let findings = scanner.scan(&apex(), &ctx()).await.unwrap();

    // The passive source was queried through `send`: it recorded the crt.sh-style
    // query (percent-encoded wildcard + JSON output) and carried a User-Agent.
    let source_requests = source.requests.lock().unwrap();
    assert_eq!(
        source_requests.len(),
        1,
        "the passive source was queried once"
    );
    let head = &source_requests[0];
    assert!(
        head.contains("output=json"),
        "crt.sh JSON output requested: {head}"
    );
    assert!(
        head.contains("q=%25."),
        "the SQL-LIKE wildcard is percent-encoded: {head}"
    );
    assert!(
        head.to_lowercase().contains("user-agent:"),
        "the query carried a rotating User-Agent (went through send): {head}"
    );

    // The discovered live host was probed and reported.
    assert_eq!(
        findings.len(),
        1,
        "one discovered host, one finding: {findings:#?}"
    );
    assert_eq!(findings[0].status, Status::Info);
    assert_eq!(
        findings[0].evidence.as_ref().unwrap()["host"],
        live.authority
    );
    assert!(
        !live.requests.lock().unwrap().is_empty(),
        "the host was probed"
    );
}

/// Task 1 + spec "Selectable by id": the scanner registers via `register_builtins`
/// and is created by its stable id.
#[tokio::test]
async fn registered_via_builtins_and_selectable() {
    let dir = tempfile::tempdir().unwrap();
    let db = DatabaseManager::connect(dir.path().join("abyssum.db"))
        .await
        .unwrap();
    let store = db.reference_store();

    let mut registry = ScannerRegistry::new(Arc::new(Config::default()));
    register_builtins(&mut registry, &store);

    assert!(registry.contains(SubdomainReconScanner::ID));
    assert!(
        registry
            .available()
            .contains(&"subdomain_recon".to_string())
    );
    let scanner = registry.create("subdomain_recon").unwrap();
    assert_eq!(scanner.id(), "subdomain_recon");
}

/// Task 6 (brute-force OFF): with brute-force disabled (the default config) the
/// scanner never touches the DoH resolver, even when a brute-force wordlist is
/// present — reconnaissance stays passive.
#[tokio::test]
async fn bruteforce_disabled_does_no_wordlist_probing() {
    let doh = start_mock(200, DOH_EXISTS).await;
    let live = start_mock(200, "<html>up</html>").await;

    // Passive discovery is empty; a brute-force candidate is supplied but must be
    // ignored while the feature is off.
    let scanner = SubdomainReconScanner::with_candidates(std::iter::empty::<String>())
        .with_bruteforce_candidates([live.authority.clone()])
        .with_doh_base(Url::parse(&format!("http://{}/", doh.authority)).unwrap());

    let findings = scanner.scan(&apex(), &ctx()).await.unwrap();

    assert!(
        findings.is_empty(),
        "nothing is discovered when off: {findings:#?}"
    );
    assert!(
        doh.requests.lock().unwrap().is_empty(),
        "the DoH resolver is never queried when brute-force is off"
    );
    assert!(
        live.requests.lock().unwrap().is_empty(),
        "no wordlist candidate is probed when brute-force is off"
    );
}

/// Task 6 (brute-force ON): with brute-force enabled and a stubbed resolver, a
/// candidate the resolver confirms exists is routed into the same liveness
/// evaluation as a passive one and surfaces as a finding. The existence test goes
/// through the paced `send` path (percent-encoded DoH query + rotating UA).
#[tokio::test]
async fn bruteforce_enabled_discovers_and_evaluates_existing_candidate() {
    let doh = start_mock(200, DOH_EXISTS).await;
    let live = start_mock(200, "<html><body>real service</body></html>").await;

    let scanner = SubdomainReconScanner::with_candidates(std::iter::empty::<String>())
        .with_bruteforce_candidates([live.authority.clone()])
        .with_doh_base(Url::parse(&format!("http://{}/", doh.authority)).unwrap());

    let findings = scanner.scan(&apex(), &ctx_bruteforce()).await.unwrap();

    // The resolver was queried for the candidate, through the paced send path.
    let doh_requests = doh.requests.lock().unwrap();
    assert_eq!(
        doh_requests.len(),
        1,
        "the candidate was existence-tested once"
    );
    let head = &doh_requests[0];
    assert!(head.contains("type=A"), "an A record was queried: {head}");
    assert!(
        head.contains("name=127.0.0.1"),
        "the candidate name was queried: {head}"
    );
    assert!(
        head.to_lowercase().contains("user-agent:"),
        "the existence test carried a rotating User-Agent (went through send): {head}"
    );

    // The confirmed candidate was probed and reported exactly like a passive one.
    assert_eq!(
        findings.len(),
        1,
        "the confirmed candidate yields a finding: {findings:#?}"
    );
    assert_eq!(findings[0].status, Status::Info);
    assert_eq!(
        findings[0].evidence.as_ref().unwrap()["host"],
        live.authority
    );
    assert!(
        !live.requests.lock().unwrap().is_empty(),
        "the confirmed host was probed"
    );
}

/// Task 3 (existence gate): a candidate the resolver reports as NXDOMAIN is not
/// probed for liveness — the DoH check gates the liveness probe.
#[tokio::test]
async fn bruteforce_skips_candidate_that_does_not_resolve() {
    let doh = start_mock(200, DOH_NXDOMAIN).await;
    let live = start_mock(200, "<html>up</html>").await;

    let scanner = SubdomainReconScanner::with_candidates(std::iter::empty::<String>())
        .with_bruteforce_candidates([live.authority.clone()])
        .with_doh_base(Url::parse(&format!("http://{}/", doh.authority)).unwrap());

    let findings = scanner.scan(&apex(), &ctx_bruteforce()).await.unwrap();

    assert!(
        findings.is_empty(),
        "a non-existent candidate yields nothing: {findings:#?}"
    );
    assert_eq!(
        doh.requests.lock().unwrap().len(),
        1,
        "the candidate was existence-tested"
    );
    assert!(
        live.requests.lock().unwrap().is_empty(),
        "a candidate that does not resolve is never probed for liveness"
    );
}

/// Task 1 (scope invariant, end to end): a candidate outside the target's apex is
/// discarded and never contacted, even though a live server answers at that
/// address. Proves the invariant holds where the request is formed, not only at
/// candidate generation.
#[tokio::test]
async fn out_of_apex_candidate_is_never_probed() {
    // A live server stands in for a third-party host the scanner must never touch.
    let foreign = start_mock(200, "<html>someone else's site</html>").await;

    // The apex is a real domain; the candidate resolves to the foreign localhost
    // server, nowhere near the apex, so it must be discarded before any probe.
    let target = Target::parse("http://example.com").unwrap();
    let scanner = SubdomainReconScanner::with_candidates([foreign.authority.clone()]);
    let findings = scanner.scan(&target, &ctx()).await.unwrap();

    assert!(
        findings.is_empty(),
        "an out-of-apex host yields no finding: {findings:#?}"
    );
    assert!(
        foreign.requests.lock().unwrap().is_empty(),
        "the scanner must issue no request to a host outside the apex",
    );
}

/// Tasks 4 + 5 + 6 (authority escape blocked at the probe boundary): a candidate
/// crafted to reinterpret the URL authority and reach a third party — a name that
/// *ends with* the apex yet a naive parse resolves to a foreign address — is
/// discarded before any request. The foreign server is live, so a regression that
/// probed it would be caught by its (asserted-empty) request log.
#[tokio::test]
async fn authority_escaping_candidate_reaches_no_foreign_host() {
    let foreign = start_mock(200, "<html>a third party</html>").await;

    // `127.0.0.1:PORT/.example.com` parses to host `127.0.0.1` (the foreign
    // server), even though it ends with the apex — the classic escape.
    let crafted = format!("{}/.example.com", foreign.authority);
    let target = Target::parse("http://example.com").unwrap();
    let scanner = SubdomainReconScanner::with_candidates([crafted]);
    let findings = scanner.scan(&target, &ctx()).await.unwrap();

    assert!(
        findings.is_empty(),
        "the crafted candidate yields nothing: {findings:#?}"
    );
    assert!(
        foreign.requests.lock().unwrap().is_empty(),
        "no request may reach a host outside the apex, even via an authority escape",
    );
}

/// Whether `findings` contains a source-availability note naming an unavailable
/// discovery source (evidence carries `results_may_be_incomplete`).
fn source_unavailable_finding(
    findings: &[abyssum_core::Finding],
) -> Option<&abyssum_core::Finding> {
    findings.iter().find(|f| {
        f.evidence
            .as_ref()
            .and_then(|e| e["results_may_be_incomplete"].as_bool())
            == Some(true)
    })
}

/// Task 6 (failing source): a passive source that cannot be reached yields an
/// informational finding naming the source and stating results may be incomplete —
/// so an empty result is never mistaken for "this apex has no subdomains".
#[tokio::test]
async fn failing_passive_source_reports_unavailable() {
    // A bound-then-dropped authority: the source query is refused (transport error).
    let dead = dead_authority().await;
    let scanner =
        SubdomainReconScanner::with_source_base(Url::parse(&format!("http://{dead}/")).unwrap());

    let findings = scanner.scan(&apex(), &ctx()).await.unwrap();

    let note = source_unavailable_finding(&findings).expect("a source-availability finding");
    assert_eq!(note.status, Status::Info);
    assert_eq!(note.severity, Severity::Info);
    assert!(
        note.title.contains("crt.sh"),
        "the finding names the source: {}",
        note.title
    );
    // A failed (unreachable) source carries no HTTP status.
    assert!(note.evidence.as_ref().unwrap()["status"].is_null());
}

/// Task 6 (non-2xx source): a passive source that answers with a non-success status
/// (the observed crt.sh 502) yields an informational finding naming the source and
/// its status.
#[tokio::test]
async fn non_success_passive_source_reports_status() {
    let source = start_mock(502, "Bad Gateway").await;
    let scanner = SubdomainReconScanner::with_source_base(
        Url::parse(&format!("http://{}/", source.authority)).unwrap(),
    );

    let findings = scanner.scan(&apex(), &ctx()).await.unwrap();

    let note = source_unavailable_finding(&findings).expect("a source-availability finding");
    assert_eq!(note.status, Status::Info);
    assert!(note.title.contains("crt.sh"));
    assert_eq!(note.evidence.as_ref().unwrap()["status"], 502);
}

/// Task 6 (healthy but empty): a source that responds normally yet lists no names
/// yields no source-availability finding — the empty result reflects the source's
/// answer, not a failure to consult it.
#[tokio::test]
async fn healthy_empty_passive_source_reports_nothing() {
    // A well-formed crt.sh response with zero entries.
    let source = start_mock(200, "[]").await;
    let scanner = SubdomainReconScanner::with_source_base(
        Url::parse(&format!("http://{}/", source.authority)).unwrap(),
    );

    let findings = scanner.scan(&apex(), &ctx()).await.unwrap();

    assert!(
        findings.is_empty(),
        "a healthy empty source yields no findings at all: {findings:#?}"
    );
}

/// Task 5 (brute-force DoH): with brute-force enabled, a resolver that is
/// unavailable yields a single source-availability finding (not one per candidate),
/// so operators know the brute-force pass could not confirm names.
#[tokio::test]
async fn failing_bruteforce_resolver_reports_unavailable_once() {
    // The resolver authority is dead: every existence test is refused.
    let dead_doh = dead_authority().await;
    let scanner = SubdomainReconScanner::with_candidates(std::iter::empty::<String>())
        .with_bruteforce_candidates(["a.127.0.0.1", "b.127.0.0.1", "c.127.0.0.1"])
        .with_doh_base(Url::parse(&format!("http://{dead_doh}/")).unwrap());

    let findings = scanner.scan(&apex(), &ctx_bruteforce()).await.unwrap();

    let notes: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.evidence
                .as_ref()
                .and_then(|e| e["results_may_be_incomplete"].as_bool())
                == Some(true)
        })
        .collect();
    assert_eq!(
        notes.len(),
        1,
        "a repeatedly-failing resolver is reported once, not per candidate: {findings:#?}"
    );
    assert!(notes[0].title.contains("DNS-over-HTTPS"));
}

/// A hostless / pathful target is rejected before any traffic: recon needs a bare
/// apex host.
#[tokio::test]
async fn rejects_target_with_a_path() {
    let scanner = SubdomainReconScanner::new();
    let with_path = Target::parse("https://example.com/api/v1").unwrap();
    assert!(scanner.scan(&with_path, &ctx()).await.is_err());
}
