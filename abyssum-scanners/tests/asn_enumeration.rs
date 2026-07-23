//! Integration tests for the ASN / netblock-enumeration scanner.
//!
//! Every test runs against hand-rolled, in-process mock HTTP servers bound to
//! random localhost ports — **no real network, no external deps, no real DNS**.
//! The registration-data source is a local mock that answers the IP-to-ASN lookup
//! (`prefix-overview`) and the ASN-prefixes lookup (`announced-prefixes`) with
//! stubbed RIPEstat-style JSON; domain resolution is a local DoH mock. This proves the full
//! flow (resolve → look up ASN → enumerate netblocks → report) without touching a
//! real registry, and that only those registration-data queries are issued — the
//! enumerated ranges are never contacted (no routing/scan action).

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
use abyssum_scanners::{AsnEnumerationScanner, register_builtins};

// --- Mock HTTP server -------------------------------------------------------

/// A running mock: its authority (`127.0.0.1:PORT`) and the request heads it
/// received (request line + headers), for asserting what was queried.
struct Mock {
    authority: String,
    requests: Arc<Mutex<Vec<String>>>,
}

/// Start a registration-data source mock: it answers `announced-prefixes` requests
/// with `asn_body` and every other request (the `prefix-overview` lookup) with
/// `ip_body`, so one server serves both stages and tests can assert both queries
/// were made. A DoH mock is just a source mock whose bodies are the same DNS JSON.
async fn start_mock(ip_body: &'static str, asn_body: &'static str) -> Mock {
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
                handle_conn(sock, ip_body, asn_body, requests).await;
            });
        }
    });

    Mock {
        authority,
        requests,
    }
}

/// A single-body mock (used for the DoH resolver: every request gets the same DNS
/// JSON regardless of path).
async fn start_single(body: &'static str) -> Mock {
    start_mock(body, body).await
}

/// Bind a port and immediately drop the listener, yielding an authority nothing
/// listens on: a query to it is refused (transport error) — a source that cannot
/// be reached.
async fn dead_authority() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let authority = listener.local_addr().unwrap().to_string();
    drop(listener);
    authority
}

async fn handle_conn(
    mut sock: TcpStream,
    ip_body: &'static str,
    asn_body: &'static str,
    requests: Arc<Mutex<Vec<String>>>,
) {
    let head = read_request_head(&mut sock).await.unwrap_or_default();
    // Route by path: the ASN-prefixes stage hits `announced-prefixes`; everything
    // else is the `prefix-overview` IP lookup (or the DoH query).
    let body = if head.contains("announced-prefixes") {
        asn_body
    } else {
        ip_body
    };
    requests.lock().unwrap().push(head);

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.flush().await;
    let _ = sock.shutdown().await;
}

/// Read the request head (up to the blank-line terminator).
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

// --- Scan helpers -----------------------------------------------------------

fn ctx() -> ScanContext {
    ScanContext::new(
        Arc::new(Config::default()),
        RateLimiter::new(Duration::ZERO, Duration::ZERO),
        Arc::new(SingleUserAgent::default()),
        CancellationToken::new(),
    )
}

/// Stubbed RIPEstat `prefix-overview` IP-to-ASN lookup: 8.8.8.8 belongs to AS15169
/// (holder "GOOGLE, US"), covered by 8.8.8.0/24.
const IP_LOOKUP: &str = r#"{
    "status": "ok",
    "data": {
        "announced": true,
        "asns": [ {"asn": 15169, "holder": "GOOGLE, US"} ],
        "resource": "8.8.8.0/24",
        "type": "prefix"
    }
}"#;

/// Stubbed RIPEstat `announced-prefixes` response: three announced netblocks (v4 +
/// v6 in one `prefixes` array) for AS15169.
const ASN_PREFIXES: &str = r#"{
    "status": "ok",
    "data": {
        "prefixes": [
            {"prefix": "8.8.8.0/24", "timelines": []},
            {"prefix": "8.8.4.0/24", "timelines": []},
            {"prefix": "2001:4860::/32", "timelines": []}
        ],
        "resource": "15169"
    }
}"#;

/// A DoH JSON body that resolves example.com to 8.8.8.8 (an A record).
const DOH_A: &str = r#"{"Status":0,"Answer":[{"name":"example.com","type":1,"data":"8.8.8.8"}]}"#;

fn source_url(mock: &Mock) -> Url {
    Url::parse(&format!("http://{}/", mock.authority)).unwrap()
}

// --- Tests ------------------------------------------------------------------

/// Task 7 (the required no-network test): a stubbed RDAP-style response yields the
/// expected ASN and netblocks, naming the owning organization, and only the
/// registration-data queries are issued — no routing action, no scan of the
/// enumerated ranges. The domain is resolved over the paced DoH path, and every
/// query carries a rotating User-Agent (it went through `send`).
#[tokio::test]
async fn stubbed_rdap_yields_asn_and_netblocks_no_routing_action() {
    let source = start_mock(IP_LOOKUP, ASN_PREFIXES).await;
    let doh = start_single(DOH_A).await;

    let scanner = AsnEnumerationScanner::new()
        .with_source_base(source_url(&source))
        .with_doh_base(source_url(&doh));

    let target = Target::parse("http://example.com").unwrap();
    let findings = scanner.scan(&target, &ctx()).await.unwrap();

    // One ASN finding + one finding per netblock (3 netblocks) = 4 findings.
    assert_eq!(
        findings.len(),
        4,
        "ASN + 3 netblocks reported: {findings:#?}"
    );

    // The ASN finding names AS15169 and the owning organization.
    let asn = findings
        .iter()
        .find(|f| f.title.contains("belongs to"))
        .expect("an ASN finding is reported");
    assert_eq!(asn.status, Status::Info);
    assert_eq!(asn.severity, Severity::Info);
    assert!(asn.title.contains("AS15169"));
    assert!(asn.title.contains("GOOGLE, US"));
    let ev = asn.evidence.as_ref().unwrap();
    assert_eq!(ev["asn"], 15169);
    assert_eq!(ev["organization"], "GOOGLE, US");
    assert_eq!(ev["resolved_ip"], "8.8.8.8");

    // Every enumerated netblock is reported, each naming the ASN + organization.
    for cidr in ["8.8.8.0/24", "8.8.4.0/24", "2001:4860::/32"] {
        let nb = findings
            .iter()
            .find(|f| f.evidence.as_ref().and_then(|e| e["netblock"].as_str()) == Some(cidr))
            .unwrap_or_else(|| panic!("netblock {cidr} is reported"));
        assert!(nb.title.contains("AS15169"));
        assert_eq!(nb.evidence.as_ref().unwrap()["organization"], "GOOGLE, US");
    }

    // The source was queried exactly twice: the IP lookup and the ASN prefixes —
    // no request to any enumerated range (no routing/scan action).
    let source_requests = source.requests.lock().unwrap();
    assert_eq!(
        source_requests.len(),
        2,
        "only the IP lookup and the ASN-prefixes query are issued: {source_requests:#?}"
    );
    assert!(
        source_requests
            .iter()
            .any(|r| r.contains("prefix-overview") && r.contains("resource=8.8.8.8")),
        "the resolved IP was looked up: {source_requests:#?}"
    );
    assert!(
        source_requests
            .iter()
            .any(|r| r.contains("announced-prefixes") && r.contains("resource=AS15169")),
        "the ASN's prefixes were enumerated: {source_requests:#?}"
    );
    // Both source queries went through the paced send path (rotating User-Agent).
    assert!(
        source_requests
            .iter()
            .all(|r| r.to_lowercase().contains("user-agent:")),
        "source queries carried a User-Agent (went through send): {source_requests:#?}"
    );

    // The domain was resolved once, over the paced DoH path.
    let doh_requests = doh.requests.lock().unwrap();
    assert_eq!(doh_requests.len(), 1, "the domain was resolved once");
    assert!(doh_requests[0].contains("name=example.com"));
    assert!(doh_requests[0].contains("type=A"));
    assert!(doh_requests[0].to_lowercase().contains("user-agent:"));
}

/// An IP-literal target skips DoH entirely and is looked up directly.
#[tokio::test]
async fn ip_literal_target_skips_doh() {
    let source = start_mock(IP_LOOKUP, ASN_PREFIXES).await;
    let doh = start_single(DOH_A).await;

    let scanner = AsnEnumerationScanner::new()
        .with_source_base(source_url(&source))
        .with_doh_base(source_url(&doh));

    let target = Target::parse("http://8.8.8.8").unwrap();
    let findings = scanner.scan(&target, &ctx()).await.unwrap();

    assert_eq!(findings.len(), 4, "ASN + 3 netblocks: {findings:#?}");
    assert!(
        doh.requests.lock().unwrap().is_empty(),
        "an IP-literal target is never resolved over DoH"
    );
    assert!(
        source
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.contains("prefix-overview") && r.contains("resource=8.8.8.8")),
        "the IP literal was looked up directly"
    );
}

/// A domain that does not resolve (NXDOMAIN) yields nothing — the source is never
/// queried.
#[tokio::test]
async fn unresolvable_domain_yields_nothing() {
    let source = start_mock(IP_LOOKUP, ASN_PREFIXES).await;
    let doh = start_single(r#"{"Status":3}"#).await;

    let scanner = AsnEnumerationScanner::new()
        .with_source_base(source_url(&source))
        .with_doh_base(source_url(&doh));

    let target = Target::parse("http://nx.example.com").unwrap();
    let findings = scanner.scan(&target, &ctx()).await.unwrap();

    assert!(findings.is_empty(), "nothing to enumerate: {findings:#?}");
    assert!(
        source.requests.lock().unwrap().is_empty(),
        "the registration-data source is not queried when resolution fails"
    );
}

/// Task 5 (registration-data source unavailable): when the domain resolves but the
/// registration-data source cannot be reached, the scan emits an informational
/// finding naming the source and stating results may be incomplete — instead of a
/// silently-empty result the operator would read as "no footprint".
#[tokio::test]
async fn unavailable_registration_source_reports_unavailable() {
    let doh = start_single(DOH_A).await; // resolution succeeds (→ 8.8.8.8)
    let dead_source = dead_authority().await; // the registration-data source is down

    let scanner = AsnEnumerationScanner::new()
        .with_source_base(Url::parse(&format!("http://{dead_source}/")).unwrap())
        .with_doh_base(source_url(&doh));

    let target = Target::parse("http://example.com").unwrap();
    let findings = scanner.scan(&target, &ctx()).await.unwrap();

    // The only finding is the source-availability note (no ASN could be looked up).
    assert_eq!(
        findings.len(),
        1,
        "just the source-availability note: {findings:#?}"
    );
    let note = &findings[0];
    assert_eq!(note.status, Status::Info);
    assert_eq!(note.severity, Severity::Info);
    assert!(
        note.title.contains("RIPEstat"),
        "the finding names the registration-data source: {}",
        note.title
    );
    let ev = note.evidence.as_ref().unwrap();
    assert_eq!(ev["results_may_be_incomplete"], true);
    assert!(
        ev["status"].is_null(),
        "an unreachable source carries no status"
    );
}

/// Task 1 + "Selectable by id": the scanner registers via `register_builtins` and
/// is created by its stable id.
#[tokio::test]
async fn registered_via_builtins_and_selectable() {
    let dir = tempfile::tempdir().unwrap();
    let db = DatabaseManager::connect(dir.path().join("abyssum.db"))
        .await
        .unwrap();
    let store = db.reference_store();

    let mut registry = ScannerRegistry::new(Arc::new(Config::default()));
    register_builtins(&mut registry, &store);

    assert!(registry.contains(AsnEnumerationScanner::ID));
    assert!(
        registry
            .available()
            .contains(&"asn_enumeration".to_string())
    );
    let scanner = registry.create("asn_enumeration").unwrap();
    assert_eq!(scanner.id(), "asn_enumeration");
}
