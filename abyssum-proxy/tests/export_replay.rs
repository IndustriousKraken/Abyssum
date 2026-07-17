//! Export + programmatic-access + replay, end to end.
//!
//! Covers f03's spec scenarios: HAR/OpenAPI/raw export of a captured set produces
//! the expected shapes; the read API returns matching exchanges; and a replay with
//! a modified header goes out through the **paced** send path (pacing floor +
//! rotating User-Agent) and its response is captured like any other exchange.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use abyssum_core::{
    CancellationToken, Config, RateLimiter, RotatingUserAgent, ScanContext, UserAgentRotation,
};
use abyssum_proxy::{
    ApiState, CapturedExchange, ExportFormat, ReplayModifications, Replayer, TrafficQuery,
    TrafficStore,
};
use bytes::Bytes;
use chrono::Utc;
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::TcpListener;

/// A destination that echoes the request's `x-mod` and `User-Agent` headers back in
/// response headers, so a replay can prove what actually went out on the wire.
async fn echo(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let mod_hdr = req
        .headers()
        .get("x-mod")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let ua = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let resp = Response::builder()
        .header("x-echo-mod", mod_hdr)
        .header("x-echo-ua", ua)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from_static(b"{\"ok\":true}")))
        .unwrap();
    Ok(resp)
}

/// Spawn the echo destination on an ephemeral port; return its address.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(echo))
                    .await;
            });
        }
    });
    addr
}

/// Record a minimal GET exchange aimed at `url` into `store`, returning its row id.
async fn seed_exchange(store: &TrafficStore, method: &str, url: &str, endpoint: &str) -> i64 {
    store
        .record(&CapturedExchange {
            method: method.into(),
            url: url.into(),
            host: "127.0.0.1".into(),
            endpoint: endpoint.into(),
            query: None,
            params: Vec::new(),
            req_headers: vec![("x-mod".into(), "original".into())],
            req_body: Vec::new(),
            req_body_truncated: false,
            status: 200,
            resp_headers: vec![("content-type".into(), "application/json".into())],
            resp_body: b"{}".to_vec(),
            resp_body_truncated: false,
            started_at: Utc::now(),
            duration_ms: 1,
        })
        .await
        .unwrap()
}

/// Build a replayer over `store` with a controlled pacing floor and a known,
/// two-identity rotating User-Agent pool.
fn replayer_with_floor(store: TrafficStore, floor: Duration) -> Replayer {
    let ctx = ScanContext::new(
        Arc::new(Config::default()),
        RateLimiter::new(floor, floor),
        Arc::new(RotatingUserAgent::new(
            vec!["UA-Alpha/1.0".into(), "UA-Beta/1.0".into()],
            UserAgentRotation::PerRequest,
        )),
        CancellationToken::new(),
    );
    Replayer::new(ctx, store, 0)
}

#[tokio::test]
async fn replay_with_modified_header_goes_out_paced_and_is_captured() {
    let dir = tempfile::tempdir().unwrap();
    let store = TrafficStore::open(dir.path().join("traffic.db"))
        .await
        .unwrap();
    let dest = spawn_echo().await;

    let url = format!("http://{dest}/echo");
    let id = seed_exchange(&store, "GET", &url, "/echo").await;

    // No artificial delay on the first replay so the test stays fast; the pacing
    // *floor* is exercised by the timed second replay below.
    let replayer = replayer_with_floor(store.clone(), Duration::from_millis(250));

    // Replay with a modified `x-mod` header.
    let mods = ReplayModifications {
        headers: Some(vec![("x-mod".into(), "changed".into())]),
        ..Default::default()
    };
    let result = replayer.replay_stored(id, &mods).await.unwrap();

    // The destination received the *modified* header (echoed back), proving the
    // modified request actually went out.
    let echoed_mod = result
        .exchange
        .resp_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-echo-mod"))
        .map(|(_, v)| v.as_str());
    assert_eq!(echoed_mod, Some("changed"));

    // It went out through `ScanContext::send`: the request carried a rotating
    // User-Agent from the pool (not the operator's headers, not empty).
    let echoed_ua = result
        .exchange
        .resp_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-echo-ua"))
        .map(|(_, v)| v.clone())
        .unwrap();
    assert!(
        echoed_ua == "UA-Alpha/1.0" || echoed_ua == "UA-Beta/1.0",
        "replay must stamp a rotating UA; got {echoed_ua:?}"
    );

    // The response was captured like any other exchange — it is now in the store.
    let rows = store
        .query(&TrafficQuery::new().by_endpoint("/echo"))
        .await
        .unwrap();
    assert_eq!(rows.len(), 2, "base + replayed exchange are both stored");
    assert!(rows.iter().any(|r| r.id == result.id));

    // Replay respects the pacing floor: the first request to a fresh host is free,
    // but a second replay to the same host waits at least the floor.
    let start = Instant::now();
    replayer.replay_stored(id, &mods).await.unwrap();
    assert!(
        start.elapsed() >= Duration::from_millis(150),
        "second replay to the same host must be paced (floor 250ms); waited {:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn export_produces_expected_shapes_for_a_captured_set() {
    let dir = tempfile::tempdir().unwrap();
    let store = TrafficStore::open(dir.path().join("traffic.db"))
        .await
        .unwrap();

    seed_exchange(
        &store,
        "GET",
        "http://127.0.0.1/api/users/1",
        "/api/users/1",
    )
    .await;
    seed_exchange(
        &store,
        "GET",
        "http://127.0.0.1/api/users/2",
        "/api/users/2",
    )
    .await;
    seed_exchange(&store, "POST", "http://127.0.0.1/api/orders", "/api/orders").await;

    let rows = store.query(&TrafficQuery::new()).await.unwrap();
    assert_eq!(rows.len(), 3);

    // HAR: valid JSON with one entry per captured exchange.
    let har: Value = serde_json::from_str(&ExportFormat::Har.export(&rows)).unwrap();
    assert_eq!(har["log"]["entries"].as_array().unwrap().len(), 3);

    // OpenAPI: best-effort, with the two id paths collapsed to one template.
    let oas: Value = serde_json::from_str(&ExportFormat::OpenApi.export(&rows)).unwrap();
    assert!(oas["paths"]["/api/users/{id}"].is_object());
    assert!(oas["paths"]["/api/orders"]["post"].is_object());

    // Raw: verbatim text mentioning each request line.
    let raw = ExportFormat::Raw.export(&rows);
    assert!(raw.contains("GET /api/users/1 HTTP/1.1"));
    assert!(raw.contains("POST /api/orders HTTP/1.1"));
}

#[tokio::test]
async fn read_api_queries_exports_and_replays_over_the_wire() {
    let dir = tempfile::tempdir().unwrap();
    let store = TrafficStore::open(dir.path().join("traffic.db"))
        .await
        .unwrap();
    let dest = spawn_echo().await;

    let url = format!("http://{dest}/echo");
    let id = seed_exchange(&store, "GET", &url, "/echo").await;

    // Start the read/replay API on an ephemeral port.
    let replayer = replayer_with_floor(store.clone(), Duration::ZERO);
    let state = Arc::new(ApiState {
        store: store.clone(),
        replayer,
        token: None,
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = listener.local_addr().unwrap();
    tokio::spawn(async move { abyssum_proxy::api::serve(listener, state).await });

    let client = reqwest::Client::new();

    // The read query returns the captured exchange (external caller queries the API).
    let rows: Value = client
        .get(format!("http://{api}/exchanges?endpoint=/echo"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["endpoint"], "/echo");

    // Export over the API returns a HAR document.
    let har: Value = client
        .get(format!("http://{api}/export/har"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(har["log"]["version"], "1.2");

    // Replay with a modified header via the API; the modified request goes out
    // (echoed back) and the response is captured.
    let replayed: Value = client
        .post(format!("http://{api}/replay"))
        .json(&json!({ "id": id, "headers": { "x-mod": "via-api" } }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let echoed = replayed["response_headers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["name"] == "x-echo-mod")
        .map(|h| h["value"].clone());
    assert_eq!(echoed, Some(json!("via-api")));

    // The replay was captured: the store now holds two /echo exchanges.
    assert_eq!(
        store
            .query(&TrafficQuery::new().by_endpoint("/echo"))
            .await
            .unwrap()
            .len(),
        2
    );
}

#[tokio::test]
async fn read_api_rejects_requests_without_the_configured_bearer_token() {
    let dir = tempfile::tempdir().unwrap();
    let store = TrafficStore::open(dir.path().join("traffic.db"))
        .await
        .unwrap();
    seed_exchange(&store, "GET", "http://127.0.0.1/api/x", "/api/x").await;

    // Gate the API behind a shared-secret token.
    let replayer = replayer_with_floor(store.clone(), Duration::ZERO);
    let state = Arc::new(ApiState {
        store: store.clone(),
        replayer,
        token: Some("s3cret".into()),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api = listener.local_addr().unwrap();
    tokio::spawn(async move { abyssum_proxy::api::serve(listener, state).await });

    let client = reqwest::Client::new();

    // No token → 401, and the captured credentials are not disclosed.
    let unauth = client
        .get(format!("http://{api}/exchanges"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Wrong token → 401.
    let wrong = client
        .get(format!("http://{api}/exchanges"))
        .bearer_auth("nope")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), reqwest::StatusCode::UNAUTHORIZED);

    // Correct token → 200 with the captured exchange.
    let ok = client
        .get(format!("http://{api}/exchanges"))
        .bearer_auth("s3cret")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), reqwest::StatusCode::OK);
    let rows: Value = ok.json().await.unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
}
