//! Integration tests for the custom-requests tool's send path.
//!
//! Every test runs against a hand-rolled, in-process mock HTTP server bound to a
//! random localhost port — **no real targets, no external deps**. The mock records
//! the full request (method, headers, body) so the send test can assert it arrived
//! intact, and replies with a canned response so the capture path is exercised
//! end-to-end. The transport-error test points at a port with no listener to prove
//! a failed request is captured into the result rather than crashing.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use abyssum_core::custom_request::{execute, OutputFormat};
use abyssum_core::{CaptureResult, CustomRequestSpec, RateLimiter};

// --- Mock HTTP server -------------------------------------------------------

/// The canned response a mock returns to every request.
#[derive(Clone)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

/// One fully-recorded request: the request line plus headers and body.
#[derive(Clone, Default)]
struct Recorded {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

struct Mock {
    base: String,
    recorded: Arc<Mutex<Vec<Recorded>>>,
}

impl Mock {
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base.trim_end_matches('/'), path)
    }

    fn last(&self) -> Recorded {
        self.recorded.lock().unwrap().last().cloned().unwrap()
    }
}

async fn start_mock(reply: Reply) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}/");
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let recorded_bg = recorded.clone();

    tokio::spawn(async move {
        loop {
            let (sock, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let reply = reply.clone();
            let recorded = recorded_bg.clone();
            tokio::spawn(async move {
                handle_conn(sock, reply, recorded).await;
            });
        }
    });

    Mock { base, recorded }
}

async fn handle_conn(mut sock: TcpStream, reply: Reply, recorded: Arc<Mutex<Vec<Recorded>>>) {
    let Some(request) = read_request(&mut sock).await else {
        return;
    };
    recorded.lock().unwrap().push(request);

    let mut response = format!(
        "HTTP/1.1 {} {}\r\n",
        reply.status,
        reason_phrase(reply.status)
    );
    for (name, value) in &reply.headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
    response.push_str("Connection: close\r\n\r\n");
    response.push_str(&reply.body);

    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.flush().await;
    let _ = sock.shutdown().await;
}

/// Read the full request: the request line, the headers, and exactly
/// `Content-Length` body bytes (so a POST body is captured intact).
async fn read_request(sock: &mut TcpStream) -> Option<Recorded> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];

    // Read until the header terminator is seen.
    let header_end = loop {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            break buf.windows(4).position(|w| w == b"\r\n\r\n")?;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            return None;
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let first = lines.next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }

    // The body starts after the 4-byte terminator; read more until we have it all.
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }

    Some(Recorded {
        method,
        path,
        headers,
        body: String::from_utf8_lossy(&body).to_string(),
    })
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn no_pacing() -> RateLimiter {
    RateLimiter::new(Duration::ZERO, Duration::ZERO)
}

fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

// --- Tests ------------------------------------------------------------------

/// Task 5.4: the chosen method, headers, and body reach the server, and the
/// response (status, headers, body) is captured.
#[tokio::test]
async fn send_path_delivers_request_and_captures_response() {
    let mock = start_mock(Reply {
        status: 201,
        headers: vec![("X-Custom".to_string(), "yes".to_string())],
        body: r#"{"created":true}"#.to_string(),
    })
    .await;

    let spec = CustomRequestSpec::new(mock.url("/api/widgets"))
        .method("post")
        .header("X-Test-Header", "hello")
        .bearer("secret-token")
        .body(r#"{"name":"gadget"}"#);

    let outcome = execute(&spec, &no_pacing()).await;

    // The server saw exactly what we asked it to send.
    let got = mock.last();
    assert_eq!(got.method, "POST");
    assert_eq!(got.path, "/api/widgets");
    assert_eq!(find(&got.headers, "X-Test-Header"), Some("hello"));
    assert_eq!(
        find(&got.headers, "Authorization"),
        Some("Bearer secret-token")
    );
    // JSON body auto-detected its content type.
    assert_eq!(find(&got.headers, "Content-Type"), Some("application/json"));
    assert_eq!(got.body, r#"{"name":"gadget"}"#);

    // The response was captured.
    let resp = outcome.response().expect("a response should be captured");
    assert_eq!(resp.status, 201);
    assert_eq!(find(&resp.headers, "x-custom"), Some("yes"));
    assert_eq!(resp.body, r#"{"created":true}"#);
    assert_eq!(resp.redirect_count, 0);
    assert!(resp.elapsed >= Duration::ZERO);

    // The same outcome renders in both forms.
    let json = outcome.render(OutputFormat::Json);
    let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(doc["response"]["status"], 201);
    let human = outcome.render(OutputFormat::Human);
    assert!(human.contains("Status: 201"));
}

/// Task 5.5 (over the wire): a keyless request carries no auth headers and still
/// succeeds on the basis of the response alone.
#[tokio::test]
async fn keyless_request_sends_no_auth_headers() {
    let mock = start_mock(Reply {
        status: 200,
        headers: vec![("Content-Type".to_string(), "text/plain".to_string())],
        body: "pong".to_string(),
    })
    .await;

    let spec = CustomRequestSpec::new(mock.url("/ping"));
    let outcome = execute(&spec, &no_pacing()).await;

    let got = mock.last();
    assert!(find(&got.headers, "Authorization").is_none());
    assert!(find(&got.headers, "Cookie").is_none());

    let resp = outcome.response().expect("keyless request should succeed");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, "pong");
}

/// Task 5.6: a transport error (no listener on the port) yields an error-carrying
/// result rather than a crash.
#[tokio::test]
async fn transport_error_is_captured_not_fatal() {
    // Bind then immediately drop the listener so the port is closed.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let spec = CustomRequestSpec::new(format!("http://{addr}/")).timeout(Duration::from_secs(2));
    let outcome = execute(&spec, &no_pacing()).await;

    assert!(outcome.response().is_none());
    assert!(
        matches!(outcome.result, CaptureResult::Error(_)),
        "a refused connection should be captured as an error"
    );
    // The error renders in both forms without panicking.
    assert!(outcome
        .render(OutputFormat::Human)
        .contains("=== Error ==="));
    let doc: serde_json::Value = serde_json::from_str(&outcome.render(OutputFormat::Json)).unwrap();
    assert!(doc["error"].is_string());
}

/// Task 5.6 (timeout variant): a request that outlives its timeout is captured as
/// an error rather than hanging or crashing.
#[tokio::test]
async fn timeout_is_captured_not_fatal() {
    // A listener that accepts the connection but never replies.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Hold accepted connections open without ever responding.
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });

    let spec =
        CustomRequestSpec::new(format!("http://{addr}/slow")).timeout(Duration::from_millis(150));
    let outcome = execute(&spec, &no_pacing()).await;

    assert!(outcome.response().is_none());
    assert!(matches!(outcome.result, CaptureResult::Error(_)));
}

/// Pacing participation (spec: Rate-Limiting Layer Participation): the first
/// request to a host is not artificially delayed.
#[tokio::test]
async fn first_request_to_a_host_is_not_paced() {
    let mock = start_mock(Reply {
        status: 200,
        headers: Vec::new(),
        body: "ok".to_string(),
    })
    .await;

    // A limiter with a large min delay would stall a *second* request, but the
    // first to a fresh host is always free.
    let limiter = RateLimiter::new(Duration::from_secs(30), Duration::from_secs(30));
    let spec = CustomRequestSpec::new(mock.url("/first"));

    let started = std::time::Instant::now();
    let outcome = execute(&spec, &limiter).await;
    assert!(outcome.response().is_some());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the first request to a host must not be artificially delayed"
    );
}

/// A mock that 302-redirects `/start` to `/landing`, and serves `200 landed` at
/// `/landing` — enough to exercise redirect following end to end.
async fn start_redirect_mock() -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}/");
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let recorded_bg = recorded.clone();

    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let recorded = recorded_bg.clone();
            tokio::spawn(async move {
                let Some(request) = read_request(&mut sock).await else {
                    return;
                };
                let path = request.path.clone();
                recorded.lock().unwrap().push(request);
                let response = if path == "/landing" {
                    "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nlanded"
                        .to_string()
                } else {
                    "HTTP/1.1 302 Found\r\nLocation: /landing\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                };
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.flush().await;
                let _ = sock.shutdown().await;
            });
        }
    });

    Mock { base, recorded }
}

/// Task 2.2 + spec "Records the redirect outcome": following a redirect captures
/// the final URL/status and counts the hop; not following leaves the 3xx visible.
#[tokio::test]
async fn redirect_outcome_is_captured_when_following() {
    let mock = start_redirect_mock().await;

    // Not following: the 302 is captured directly, zero hops.
    let no_follow = CustomRequestSpec::new(mock.url("/start"));
    let outcome = execute(&no_follow, &no_pacing()).await;
    let resp = outcome.response().expect("a response should be captured");
    assert_eq!(resp.status, 302);
    assert_eq!(resp.redirect_count, 0);

    // Following: lands on /landing with a 200 after one hop.
    let follow = CustomRequestSpec::new(mock.url("/start")).follow_redirects(true);
    let outcome = execute(&follow, &no_pacing()).await;
    let resp = outcome.response().expect("a response should be captured");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, "landed");
    assert_eq!(resp.redirect_count, 1);
    assert!(
        resp.final_url.ends_with("/landing"),
        "final URL should be the redirect target: {}",
        resp.final_url
    );
}
