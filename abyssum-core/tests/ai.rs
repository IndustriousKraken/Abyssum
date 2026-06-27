//! Integration tests for outbound AI-assist (`analyze_finding`).
//!
//! Every test runs against a hand-rolled, in-process mock HTTP server bound to a
//! random localhost port that mimics an OpenAI-compatible `/chat/completions`
//! endpoint — **no real providers, no real targets, no external deps**. The mock
//! records each request (so the auth-header assertions can inspect what was sent)
//! and replies with a canned response so the parse path runs end to end. The
//! best-effort error paths (500, malformed body, timeout, disabled) are each proven
//! to surface a clear `Err` and never to panic or abort the caller.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use abyssum_core::{analyze_finding, AiConfig, Finding, Severity, Status, Target};

// --- Mock OpenAI-compatible server ------------------------------------------

/// The canned response a mock returns to every request.
#[derive(Clone)]
struct Reply {
    status: u16,
    body: String,
}

/// One recorded request: method, path, headers, and body.
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
    fn last(&self) -> Recorded {
        self.recorded.lock().unwrap().last().cloned().unwrap()
    }

    fn count(&self) -> usize {
        self.recorded.lock().unwrap().len()
    }
}

/// A canned OpenAI-style success body carrying `text` as the assistant content.
fn chat_body(text: &str) -> String {
    serde_json::json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": text },
            "finish_reason": "stop"
        }]
    })
    .to_string()
}

async fn start_mock(reply: Reply) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
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
    response.push_str("Content-Type: application/json\r\n");
    response.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
    response.push_str("Connection: close\r\n\r\n");
    response.push_str(&reply.body);

    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.flush().await;
    let _ = sock.shutdown().await;
}

/// Read the request line, headers, and exactly `Content-Length` body bytes.
async fn read_request(sock: &mut TcpStream) -> Option<Recorded> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];

    let header_end = loop {
        let n = sock.read(&mut tmp).await.ok()?;
        if n == 0 {
            break buf.windows(4).position(|w| w == b"\r\n\r\n")?;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > 256 * 1024 {
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
        500 => "Internal Server Error",
        _ => "OK",
    }
}

fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

// --- Fixtures ---------------------------------------------------------------

fn sample_finding() -> Finding {
    Finding::builder(
        "cors",
        Target::parse("https://api.example.com")
            .unwrap()
            .with_path("/data"),
        "Permissive CORS reflects arbitrary Origin",
    )
    .severity(Severity::High)
    .status(Status::Vulnerable)
    .evidence(serde_json::json!({ "origin": "https://evil.test", "acao": "*" }))
    .build()
}

/// An AI config pointing at `base`, keyless, with a short timeout.
fn config_for(base: &str) -> AiConfig {
    AiConfig {
        base_url: base.to_string(),
        model: "test-model".to_string(),
        api_key: None,
        timeout_seconds: 5,
        enabled: true,
        max_evidence_chars: 4000,
        temperature: 0.2,
        max_tokens: None,
    }
}

// --- Tests ------------------------------------------------------------------

/// 6.2: the happy path returns the assistant text, and the request lands on
/// `/chat/completions` as a POST carrying the finding's details.
#[tokio::test]
async fn happy_path_returns_analysis_text() {
    let mock = start_mock(Reply {
        status: 200,
        body: chat_body("This is a genuine high-severity CORS misconfiguration."),
    })
    .await;

    let analysis = analyze_finding(&config_for(&mock.base), &sample_finding())
        .await
        .expect("happy path should return analysis text");
    assert_eq!(
        analysis,
        "This is a genuine high-severity CORS misconfiguration."
    );

    let got = mock.last();
    assert_eq!(got.method, "POST");
    assert_eq!(got.path, "/chat/completions");
    // The finding's context reached the provider in the request body.
    assert!(got.body.contains("test-model"));
    assert!(got.body.contains("cors"));
    assert!(got.body.contains("evil.test"));
    assert!(got.body.contains("\"stream\":false"));
}

/// 6.3: with NO key configured the request succeeds and sends no `Authorization`.
#[tokio::test]
async fn keyless_request_sends_no_authorization_header() {
    let mock = start_mock(Reply {
        status: 200,
        body: chat_body("analysis"),
    })
    .await;

    let mut config = config_for(&mock.base);
    config.api_key = None;
    let analysis = analyze_finding(&config, &sample_finding()).await.unwrap();
    assert_eq!(analysis, "analysis");

    let got = mock.last();
    assert!(
        find(&got.headers, "Authorization").is_none(),
        "a keyless request must carry no Authorization header"
    );
}

/// 6.3 (variant): a blank key is treated as absent — still no header.
#[tokio::test]
async fn blank_key_sends_no_authorization_header() {
    let mock = start_mock(Reply {
        status: 200,
        body: chat_body("ok"),
    })
    .await;

    let mut config = config_for(&mock.base);
    config.api_key = Some("   ".to_string());
    analyze_finding(&config, &sample_finding()).await.unwrap();

    assert!(find(&mock.last().headers, "Authorization").is_none());
}

/// 6.4: with a key configured the request carries a bearer credential.
#[tokio::test]
async fn keyed_request_sends_bearer_credential() {
    let mock = start_mock(Reply {
        status: 200,
        body: chat_body("ok"),
    })
    .await;

    let mut config = config_for(&mock.base);
    config.api_key = Some("sk-test-123".to_string());
    analyze_finding(&config, &sample_finding()).await.unwrap();

    assert_eq!(
        find(&mock.last().headers, "Authorization"),
        Some("Bearer sk-test-123")
    );
}

/// 6.5: a 500 response surfaces a clear non-fatal error.
#[tokio::test]
async fn provider_500_surfaces_clear_error() {
    let mock = start_mock(Reply {
        status: 500,
        body: "upstream exploded".to_string(),
    })
    .await;

    let err = analyze_finding(&config_for(&mock.base), &sample_finding())
        .await
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("500"), "message should name the status: {msg}");
}

/// 6.5: a malformed (non-JSON / unparseable) body surfaces a clear error.
#[tokio::test]
async fn malformed_body_surfaces_clear_error() {
    let mock = start_mock(Reply {
        status: 200,
        body: "this is not json".to_string(),
    })
    .await;

    let err = analyze_finding(&config_for(&mock.base), &sample_finding())
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .to_lowercase()
        .contains("could not be interpreted"));
}

/// 6.5: an empty `choices` array is a malformed response, not analysis text.
#[tokio::test]
async fn empty_choices_surfaces_clear_error() {
    let mock = start_mock(Reply {
        status: 200,
        body: r#"{"choices":[]}"#.to_string(),
    })
    .await;

    let err = analyze_finding(&config_for(&mock.base), &sample_finding())
        .await
        .unwrap_err();
    assert!(err.to_string().to_lowercase().contains("no analysis text"));
}

/// 6.5: a request that outlives its timeout surfaces a clear timeout error rather
/// than hanging or crashing.
#[tokio::test]
async fn timeout_surfaces_clear_error() {
    // A listener that accepts connections but never replies.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });

    let mut config = config_for(&format!("http://{addr}"));
    config.timeout_seconds = 1;
    let err = analyze_finding(&config, &sample_finding())
        .await
        .unwrap_err();
    assert!(
        err.to_string().to_lowercase().contains("timed out"),
        "expected a timeout message, got: {err}"
    );
}

/// 6.5: a transport failure (no listener) surfaces a clear error, not a panic.
#[tokio::test]
async fn transport_failure_surfaces_clear_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // close the port

    let err = analyze_finding(&config_for(&format!("http://{addr}")), &sample_finding())
        .await
        .unwrap_err();
    assert!(err.to_string().to_lowercase().contains("could not reach"));
}

/// 6.6: with AI disabled the call returns a clear notice and makes NO outbound
/// request — the mock observes nothing.
#[tokio::test]
async fn disabled_returns_notice_and_makes_no_request() {
    let mock = start_mock(Reply {
        status: 200,
        body: chat_body("should never be returned"),
    })
    .await;

    let mut config = config_for(&mock.base);
    config.enabled = false;
    let err = analyze_finding(&config, &sample_finding())
        .await
        .unwrap_err();

    assert!(err.to_string().to_lowercase().contains("disabled"));
    // Give any (erroneous) outbound request a moment to land, then assert none did.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(mock.count(), 0, "a disabled provider must not be contacted");
}
