//! End-to-end: a relayed exchange is returned to the client **unmodified** and,
//! asynchronously, appears in the traffic store and is retrievable by
//! endpoint/status/time (and, for the HTTPS case, proves TLS termination lets the
//! proxy observe encrypted content).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use abyssum_proxy::{CertAuthority, ProxyServer, TrafficQuery, TrafficStore};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// The fixed response every test destination returns, so the test can assert the
/// client received it byte-for-byte through the proxy.
const DEST_BODY: &[u8] = b"hello from the destination service";

/// One request handler returning [`DEST_BODY`] with a distinctive status + header.
async fn respond(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let resp = Response::builder()
        .status(StatusCode::CREATED)
        .header("x-observed", "yes")
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from_static(DEST_BODY)))
        .unwrap();
    Ok(resp)
}

/// Spawn a plain-HTTP destination on an ephemeral port; return its address.
async fn spawn_http_destination() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(respond))
                    .await;
            });
        }
    });
    addr
}

/// Spawn a self-signed HTTPS destination (valid for `127.0.0.1`) and return its
/// address. The proxy reaches it with upstream verification disabled.
async fn spawn_https_destination() -> SocketAddr {
    let key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_der: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service_fn(respond))
                    .await;
            });
        }
    });
    addr
}

/// Start an in-process proxy over a temp store + CA; return (proxy addr, store,
/// CA cert PEM). The temp dir is leaked into a `Box` kept alive by the caller.
async fn start_proxy(dir: &std::path::Path) -> (SocketAddr, TrafficStore, String) {
    let store = TrafficStore::open(dir.join("traffic.db")).await.unwrap();
    let sink = store.spawn_writer(1024);
    let ca = Arc::new(CertAuthority::load_or_create(dir.join("ca")).await.unwrap());
    let ca_pem = ca.ca_cert_pem().to_string();
    // body_limit 0 = keep whole bodies; insecure upstream so the self-signed HTTPS
    // destination is reachable.
    let server = Arc::new(ProxyServer::new(ca, sink, 0, true).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { server.serve(listener).await });
    (addr, store, ca_pem)
}

/// Poll the store until an exchange matching `query` appears (or time out).
async fn wait_for_capture(
    store: &TrafficStore,
    query: TrafficQuery,
) -> abyssum_proxy::StoredExchange {
    for _ in 0..40 {
        let rows = store.query(&query).await.unwrap();
        if let Some(row) = rows.into_iter().next() {
            return row;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("exchange was never captured to the traffic store");
}

#[tokio::test]
async fn http_exchange_is_relayed_unmodified_and_captured() {
    let dir = tempfile::tempdir().unwrap();
    let dest = spawn_http_destination().await;
    let (proxy, store, _ca) = start_proxy(dir.path()).await;

    let before = chrono::Utc::now() - chrono::Duration::seconds(1);
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://{proxy}")).unwrap())
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://{dest}/api/widgets?id=42&sort=asc"))
        .header("x-client", "abc")
        .send()
        .await
        .unwrap();

    // Response returned unmodified: status, custom header, and body byte-for-byte.
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    assert_eq!(resp.headers().get("x-observed").unwrap(), "yes");
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), DEST_BODY);

    // Asynchronously captured and retrievable by endpoint/status/time + parameter.
    let row = wait_for_capture(&store, TrafficQuery::new().by_endpoint("/api/widgets")).await;
    assert_eq!(row.exchange.method, "GET");
    assert_eq!(row.exchange.status, 201);
    assert_eq!(row.exchange.host, "127.0.0.1");
    assert!(row.exchange.params.contains(&"id".to_string()));

    // The same row is retrievable by status and by time window.
    assert_eq!(
        store
            .query(&TrafficQuery::new().by_status(201))
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .query(&TrafficQuery::new().from(before))
            .await
            .unwrap()
            .len(),
        1
    );
    // The proxy observed the request header and the response body.
    assert!(
        store
            .query(&TrafficQuery::new().by_header("x-client"))
            .await
            .unwrap()
            .len()
            == 1
    );
    assert_eq!(row.exchange.resp_body, DEST_BODY);
}

#[tokio::test]
async fn https_exchange_is_tls_terminated_and_captured() {
    let dir = tempfile::tempdir().unwrap();
    let dest = spawn_https_destination().await;
    let (proxy, store, ca_pem) = start_proxy(dir.path()).await;

    // The client trusts the proxy's CA and routes HTTPS through it (CONNECT).
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{proxy}")).unwrap())
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .build()
        .unwrap();

    let resp = client
        .get(format!(
            "https://127.0.0.1:{}/secure?token=secret",
            dest.port()
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let body = resp.bytes().await.unwrap();
    assert_eq!(body.as_ref(), DEST_BODY);

    // TLS termination let the proxy observe the encrypted request/response.
    let row = wait_for_capture(&store, TrafficQuery::new().by_endpoint("/secure")).await;
    assert_eq!(row.exchange.status, 201);
    assert!(row.exchange.url.starts_with("https://"));
    assert!(row.exchange.params.contains(&"token".to_string()));
    assert_eq!(row.exchange.resp_body, DEST_BODY);
}
