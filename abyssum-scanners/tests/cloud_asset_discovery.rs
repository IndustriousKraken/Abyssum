//! Integration tests for the cloud-asset-discovery scanner.
//!
//! Every test runs against a hand-rolled, in-process mock HTTP server bound to a
//! random localhost port — **no real network, no external deps, no real cloud
//! provider**. The mock stands in for a cloud storage provider: it routes by the
//! candidate name in the request path so one server can answer a publicly-listable
//! bucket (`200`), an existing-but-denied bucket (`403`), and a missing bucket
//! (`404`). This proves the full flow (guess → probe → classify → report) — a
//! public bucket yields a high-severity finding, a denied one an info finding, and a
//! missing one nothing — and that the probe confirms exposure from the status alone,
//! never reading the listing body (no object enumeration).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use abyssum_core::{
    BaseScanner, Config, DatabaseManager, RateLimiter, ScanContext, ScannerRegistry, Severity,
    SingleUserAgent, Status, Target,
};
use abyssum_scanners::{CloudAssetDiscoveryScanner, register_builtins};

// --- Mock cloud-storage provider --------------------------------------------

/// A running mock: its authority (`127.0.0.1:PORT`) and the request heads it
/// received (request line + headers), for asserting what was probed.
struct Mock {
    authority: String,
    requests: Arc<Mutex<Vec<String>>>,
}

/// Start a mock storage provider. It routes by the candidate in the request path:
/// a path containing `public` → `200 OK` (publicly listable), `denied` → `403`
/// (exists but locked down), anything else → `404` (no such bucket).
async fn start_mock() -> Mock {
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
                handle_conn(sock, requests).await;
            });
        }
    });

    Mock {
        authority,
        requests,
    }
}

async fn handle_conn(mut sock: TcpStream, requests: Arc<Mutex<Vec<String>>>) {
    let head = read_request_head(&mut sock).await.unwrap_or_default();
    let request_line = head.lines().next().unwrap_or_default();
    let (status, reason) = if request_line.contains("public") {
        (200, "OK")
    } else if request_line.contains("denied") {
        (403, "Forbidden")
    } else {
        (404, "Not Found")
    };
    requests.lock().unwrap().push(head);

    // A representative listing body — the scanner must NOT read it (it classifies on
    // status alone), so its object keys must never surface in a finding.
    let body = "<ListBucketResult><Contents><Key>secret.txt</Key></Contents></ListBucketResult>";
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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

/// A single mock provider whose template routes the candidate through the path.
fn mock_provider(mock: &Mock) -> (String, String) {
    (
        "Mock Cloud".to_string(),
        format!("http://{}/{{name}}", mock.authority),
    )
}

// --- Tests ------------------------------------------------------------------

/// Task 7 (the required no-network test): a stubbed public bucket yields a
/// high-severity finding, a denied one yields an info finding, and a missing one
/// yields nothing. Every probe goes through the paced `send` path (rotating
/// User-Agent), and the returned listing body is never read (no object enumeration).
#[tokio::test]
async fn public_denied_and_missing_buckets_classified_correctly() {
    let mock = start_mock().await;

    // All three candidates share the one mock host. A `403` (denied) is a distress
    // signal to the shared rate limiter, which then backs the host off by 30s — so
    // the denied probe is ordered *last*, after the clean 200/404 ones, to keep the
    // test fast. (In production S3/Azure each bucket is its own virtual-host, so this
    // backoff never accumulates across candidates there.)
    let scanner = CloudAssetDiscoveryScanner::new()
        .with_candidates(["public-bucket", "missing-bucket", "denied-bucket"])
        .with_providers([mock_provider(&mock)]);

    let target = Target::parse("https://example.com").unwrap();
    let findings = scanner.scan(&target, &ctx()).await.unwrap();

    // The public and the denied bucket are reported; the missing one is not.
    assert_eq!(findings.len(), 2, "public + denied reported: {findings:#?}");

    let public = findings
        .iter()
        .find(|f| {
            f.evidence.as_ref().and_then(|e| e["candidate"].as_str()) == Some("public-bucket")
        })
        .expect("the public bucket is reported");
    assert_eq!(public.status, Status::Vulnerable);
    assert_eq!(public.severity, Severity::High);
    assert_eq!(public.evidence.as_ref().unwrap()["public"], true);
    assert_eq!(public.evidence.as_ref().unwrap()["status"], 200);

    let denied = findings
        .iter()
        .find(|f| {
            f.evidence.as_ref().and_then(|e| e["candidate"].as_str()) == Some("denied-bucket")
        })
        .expect("the denied bucket is reported");
    assert_eq!(denied.status, Status::Info);
    assert_eq!(denied.severity, Severity::Info);
    assert_eq!(denied.evidence.as_ref().unwrap()["public"], false);

    // The missing bucket produced no finding.
    assert!(
        !findings.iter().any(
            |f| f.evidence.as_ref().and_then(|e| e["candidate"].as_str()) == Some("missing-bucket")
        ),
        "the missing bucket is not reported: {findings:#?}"
    );

    // No finding leaked an object key from the listing body — the scanner confirmed
    // exposure from the status alone and never read the body (no exfiltration).
    for finding in &findings {
        let blob = serde_json::to_string(&finding.evidence).unwrap();
        assert!(
            !blob.contains("secret.txt"),
            "a listing object key must never surface in a finding: {finding:#?}"
        );
    }

    // Each candidate was probed exactly once (one provider), through the paced send
    // path — every probe carried a rotating User-Agent — and nothing beyond the
    // bucket root was requested (no object-key follow-ups).
    let requests = mock.requests.lock().unwrap();
    assert_eq!(requests.len(), 3, "one probe per candidate: {requests:#?}");
    assert!(
        requests
            .iter()
            .all(|r| r.to_lowercase().contains("user-agent:")),
        "probes carried a User-Agent (went through send): {requests:#?}"
    );
    for name in ["public-bucket", "denied-bucket", "missing-bucket"] {
        assert!(
            requests
                .iter()
                .any(|r| r.lines().next().unwrap_or_default().contains(name)),
            "candidate {name} was probed once at its bucket root: {requests:#?}"
        );
    }
}

/// Selectable by id: the scanner registers via `register_builtins` and is created by
/// its stable id.
#[tokio::test]
async fn registered_via_builtins_and_selectable() {
    let dir = tempfile::tempdir().unwrap();
    let db = DatabaseManager::connect(dir.path().join("abyssum.db"))
        .await
        .unwrap();
    let store = db.reference_store();

    let mut registry = ScannerRegistry::new(Arc::new(Config::default()));
    register_builtins(&mut registry, &store);

    assert!(registry.contains(CloudAssetDiscoveryScanner::ID));
    assert!(
        registry
            .available()
            .contains(&"cloud_asset_discovery".to_string())
    );
    let scanner = registry.create("cloud_asset_discovery").unwrap();
    assert_eq!(scanner.id(), "cloud_asset_discovery");
}
