//! Shared test harness for the `abyssum-web` integration tests.
//!
//! Everything is local-only (canon ethics constraint): a real in-process server
//! bound to an ephemeral port over a temp SQLite store, a cookie-aware raw HTTP/1
//! client, a hand-rolled WebSocket client that speaks the handshake and reads
//! server frames, and small local mock targets. No WebSocket client crate and no
//! real third-party targets anywhere.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use abyssum_core::Config;
use abyssum_web::{build_router, AppState};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;

/// A running server plus the in-process state, for tests that seed data or poll
/// engine state directly. Holds the temp dir so the store outlives the test.
pub struct TestApp {
    pub addr: SocketAddr,
    pub state: AppState,
    _dir: TempDir,
}

impl TestApp {
    /// Spawn a server with the default fast test config (zero pacing).
    pub async fn spawn() -> TestApp {
        Self::spawn_with(|_| {}).await
    }

    /// Spawn a server, letting the caller tweak the config (e.g. pacing for the
    /// cancellation lifecycle test).
    pub async fn spawn_with(tweak: impl FnOnce(&mut Config)) -> TestApp {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("web.db");
        let mut config = Config::default();
        config.database.path = db_path.to_string_lossy().into_owned();
        config.scanning.min_delay = 0.0;
        config.scanning.max_delay = 0.0;
        config.log.level = "warn".to_string();
        // The harness is local-only (canon ethics constraint): every mock target
        // binds to 127.0.0.1, so the SSRF guard must permit private targets here.
        // A test can flip this back off via `tweak` to exercise the guard itself.
        config.server.allow_private_custom_targets = true;
        tweak(&mut config);

        let state = AppState::build(config).await.expect("build state");
        let static_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("static");
        let app = build_router(state.clone(), static_dir);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // Connect-info make-service so the auth POSTs can read the peer IP.
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve");
        });

        TestApp {
            addr,
            state,
            _dir: dir,
        }
    }

    /// A fresh cookie-aware client against this server.
    pub fn client(&self) -> Client {
        Client {
            addr: self.addr,
            cookies: HashMap::new(),
        }
    }
}

/// A parsed HTTP response.
pub struct Resp {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Resp {
    /// The first value of a (case-insensitive) header.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The `Location` header (for redirect assertions).
    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }
}

/// A minimal cookie-aware HTTP/1.1 client over async TCP. Each call uses a fresh
/// `Connection: close` socket and reads to EOF, so body framing is trivial.
pub struct Client {
    addr: SocketAddr,
    pub cookies: HashMap<String, String>,
}

impl Client {
    /// Install a session cookie directly (tests that mint a token in-process).
    pub fn set_session(&mut self, token: &str) {
        self.cookies
            .insert("abyssum_session".to_string(), token.to_string());
    }

    /// The current CSRF token (from the `csrf` cookie), for state-changing POSTs.
    pub fn csrf(&self) -> String {
        self.cookies.get("csrf").cloned().unwrap_or_default()
    }

    pub async fn get(&mut self, path: &str) -> Resp {
        self.send("GET", path, None).await
    }

    /// POST a urlencoded form body.
    pub async fn post_form(&mut self, path: &str, body: &str) -> Resp {
        self.send("POST", path, Some(body)).await
    }

    async fn send(&mut self, method: &str, path: &str, body: Option<&str>) -> Resp {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
            self.addr
        );
        if let Some(b) = body {
            req.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        let cookie_header = self.cookie_header();
        if !cookie_header.is_empty() {
            req.push_str(&format!("Cookie: {cookie_header}\r\n"));
        }
        req.push_str("\r\n");
        if let Some(b) = body {
            req.push_str(b);
        }

        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).await.unwrap();

        let resp = parse_response(&raw);
        self.store_cookies(&resp);
        resp
    }

    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn store_cookies(&mut self, resp: &Resp) {
        for (k, v) in &resp.headers {
            if !k.eq_ignore_ascii_case("set-cookie") {
                continue;
            }
            // Take the first `name=value` segment; ignore attributes.
            let first = v.split(';').next().unwrap_or("");
            if let Some((name, value)) = first.split_once('=') {
                let (name, value) = (name.trim().to_string(), value.trim().to_string());
                let cleared = v.to_ascii_lowercase().contains("max-age=0") || value.is_empty();
                if cleared {
                    self.cookies.remove(&name);
                } else {
                    self.cookies.insert(name, value);
                }
            }
        }
    }

    /// Open a WebSocket to `path` carrying the current cookies; returns the
    /// connected client after a successful `101` handshake.
    pub async fn connect_ws(&self, path: &str) -> WsConn {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let cookie_header = self.cookie_header();
        let mut req = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
            self.addr
        );
        if !cookie_header.is_empty() {
            req.push_str(&format!("Cookie: {cookie_header}\r\n"));
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();

        let (head, leftover) = read_http_head(&mut stream).await;
        let status = status_code(&head);
        assert_eq!(status, 101, "expected a 101 upgrade, got:\n{head}");
        WsConn {
            stream,
            buf: leftover,
        }
    }
}

/// A connected WebSocket client: reads server text frames (and answers nothing —
/// the tests only observe progress).
pub struct WsConn {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl WsConn {
    /// Receive the next text frame's payload, or `None` on close/timeout.
    pub async fn recv_text(&mut self, timeout: Duration) -> Option<String> {
        loop {
            let frame = tokio::time::timeout(timeout, self.read_frame()).await;
            let (opcode, payload) = match frame {
                Ok(Some(f)) => f,
                _ => return None,
            };
            match opcode {
                0x1 => return Some(String::from_utf8_lossy(&payload).into_owned()),
                0x8 => return None,    // close
                0x9 | 0xA => continue, // ping/pong — ignore
                _ => continue,
            }
        }
    }

    async fn read_frame(&mut self) -> Option<(u8, Vec<u8>)> {
        let header = self.take(2).await?;
        let opcode = header[0] & 0x0f;
        let masked = header[1] & 0x80 != 0;
        let mut len = (header[1] & 0x7f) as usize;
        if len == 126 {
            let ext = self.take(2).await?;
            len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
        } else if len == 127 {
            let ext = self.take(8).await?;
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&ext);
            len = u64::from_be_bytes(bytes) as usize;
        }
        let mask = if masked {
            Some(self.take(4).await?)
        } else {
            None
        };
        let mut payload = self.take(len).await?;
        if let Some(mask) = mask {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
        }
        Some((opcode, payload))
    }

    /// Pull exactly `n` bytes, buffering reads from the socket.
    async fn take(&mut self, n: usize) -> Option<Vec<u8>> {
        let mut tmp = [0u8; 2048];
        while self.buf.len() < n {
            let read = self.stream.read(&mut tmp).await.ok()?;
            if read == 0 {
                return None;
            }
            self.buf.extend_from_slice(&tmp[..read]);
        }
        Some(self.buf.drain(..n).collect())
    }
}

/// Read an HTTP head (up to the blank line) and return it plus any bytes already
/// read past it (the start of the WebSocket frame stream).
async fn read_http_head(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).into_owned();
            let leftover = buf[pos + 4..].to_vec();
            return (head, leftover);
        }
        let n = stream.read(&mut tmp).await.unwrap();
        if n == 0 {
            return (String::from_utf8_lossy(&buf).into_owned(), Vec::new());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

/// Percent-encode a form value (everything but the unreserved set), so URLs,
/// newlines, and the like survive the urlencoded body intact.
pub fn enc(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_response(raw: &[u8]) -> Resp {
    let split = find(raw, b"\r\n\r\n").unwrap_or(raw.len());
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let body_start = (split + 4).min(raw.len());
    let body = String::from_utf8_lossy(&raw[body_start..]).into_owned();

    let mut lines = head.lines();
    let status = lines.next().and_then(status_token).unwrap_or(0);
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Resp {
        status,
        headers,
        body,
    }
}

fn status_code(head: &str) -> u16 {
    head.lines().next().and_then(status_token).unwrap_or(0)
}

fn status_token(line: &str) -> Option<u16> {
    line.split_whitespace().nth(1).and_then(|s| s.parse().ok())
}

// --- Local mock targets ----------------------------------------------------

/// Spawn a local HTTP server that answers every request with a permissive CORS
/// policy (which the `cors` scanner reports). An optional per-request delay slows
/// the scan so cancellation can be observed mid-flight. Returns the bound address.
pub async fn spawn_cors_mock(delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 2048];
                let _ = socket.read(&mut buf).await;
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                let response = "HTTP/1.1 200 OK\r\n\
                     Access-Control-Allow-Origin: *\r\n\
                     Access-Control-Allow-Credentials: true\r\n\
                     Content-Length: 0\r\n\
                     Connection: close\r\n\
                     \r\n";
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    addr
}

/// Spawn a trivial HTTP server returning a fixed body, for the custom-requests
/// test. Returns the bound address.
pub async fn spawn_echo_mock() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let body = "abyssum-custom-ok";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nX-Test: yes\r\nContent-Type: text/plain\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    });
    addr
}
