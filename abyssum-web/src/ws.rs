//! Live scan progress over a per-session WebSocket.
//!
//! [`Hub`] keys live scans by session id. When a scan starts, the start handler
//! registers a [`LiveFeed`] and its progress callback ticks the feed on every
//! update; the `/ws/{id}` endpoint subscribes, and on each tick renders a fresh
//! progress fragment from the live session and pushes it to the browser.
//!
//! ## Why the upgrade is hand-driven
//!
//! `abyssum-web` does not enable axum's `ws` feature: it pins
//! `tokio-tungstenite 0.28`, absent from the offline crate cache (only `0.29`).
//! So the endpoint computes the `Sec-WebSocket-Accept` handshake itself, takes
//! the raw upgraded stream via `hyper::upgrade::on`, and frames it with
//! `tokio_tungstenite::WebSocketStream::from_raw_socket`. The progress payload is
//! a server-rendered HTML fragment, not a client-side data model.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use abyssum_core::{ScanSession, SessionHandle};
use axum::body::Body;
use axum::http::header::{CONNECTION, UPGRADE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use sha1::{Digest, Sha1};
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::view;

/// The WebSocket GUID that salts the accept-key hash (RFC 6455).
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// A live scan the progress hub is tracking: the shared session state, a tick
/// channel signalled on every progress update, and the latest active scanner id.
#[derive(Clone)]
struct LiveScan {
    handle: SessionHandle,
    tx: broadcast::Sender<()>,
    scanner: Arc<Mutex<Option<String>>>,
}

/// What a scan's progress callback uses to publish updates into the hub.
#[derive(Clone)]
pub struct LiveFeed {
    tx: broadcast::Sender<()>,
    scanner: Arc<Mutex<Option<String>>>,
}

impl LiveFeed {
    /// Publish a progress update: record the active scanner and wake subscribers.
    pub fn tick(&self, scanner_id: &str) {
        if let Ok(mut slot) = self.scanner.lock() {
            *slot = Some(scanner_id.to_string());
        }
        // An error only means "no WebSocket connected"; the scan runs regardless.
        let _ = self.tx.send(());
    }

    /// Wake subscribers without changing the active scanner — used to deliver the
    /// terminal state once a run has finished.
    pub fn wake(&self) {
        let _ = self.tx.send(());
    }
}

/// Per-session live-progress registry, fed by scan callbacks and read by the
/// `/ws/{id}` endpoint. Cheap to clone (one shared map behind an `Arc`).
#[derive(Clone, Default)]
pub struct Hub {
    scans: Arc<Mutex<HashMap<Uuid, LiveScan>>>,
}

impl Hub {
    /// Register a starting scan and return the feed its callback ticks.
    pub fn start(&self, id: Uuid, handle: SessionHandle) -> LiveFeed {
        let (tx, _) = broadcast::channel(64);
        let scanner = Arc::new(Mutex::new(None));
        self.scans.lock().unwrap().insert(
            id,
            LiveScan {
                handle,
                tx: tx.clone(),
                scanner: scanner.clone(),
            },
        );
        LiveFeed { tx, scanner }
    }

    /// Stop tracking a finished scan, dropping its tick channel so any connected
    /// WebSocket sees the stream close and tears down.
    pub fn finish(&self, id: Uuid) {
        self.scans.lock().unwrap().remove(&id);
    }

    /// A snapshot of a live scan's current session state, if it is being tracked.
    /// Lets handlers render fresher state than the (initially Pending) persisted
    /// row while a scan is in flight.
    pub fn snapshot(&self, id: Uuid) -> Option<ScanSession> {
        let scans = self.scans.lock().unwrap();
        let live = scans.get(&id)?;
        live.handle.lock().ok().map(|session| session.clone())
    }

    /// A subscription to a live scan, if one is currently tracked: a tick
    /// receiver plus the shared session/scanner state to render from. Holds **no**
    /// sender clone, so the channel closes once the runner finishes.
    fn subscribe(&self, id: Uuid) -> Option<Subscription> {
        let scans = self.scans.lock().unwrap();
        let live = scans.get(&id)?;
        Some(Subscription {
            rx: live.tx.subscribe(),
            handle: live.handle.clone(),
            scanner: live.scanner.clone(),
        })
    }
}

/// A WebSocket's view of a live scan: ticks plus the state to render from.
struct Subscription {
    rx: broadcast::Receiver<()>,
    handle: SessionHandle,
    scanner: Arc<Mutex<Option<String>>>,
}

/// Build the `101 Switching Protocols` response and spawn the WebSocket task.
///
/// `subscribe` looks the session up in the hub; when the scan is already finished
/// (no live entry) `fallback` is the persisted terminal session, sent as a single
/// final fragment. The caller has already authenticated and owner-checked.
pub fn upgrade(
    hub: &Hub,
    session_id: Uuid,
    fallback: ScanSession,
    mut req: axum::extract::Request,
) -> Response {
    let headers = req.headers();
    // RFC 6455 §4.2.1/§4.4: only version 13 is supported. A missing or different
    // version is a failed negotiation — answer 426 advertising the version we speak.
    if !version_supported(headers) {
        return Response::builder()
            .status(StatusCode::UPGRADE_REQUIRED)
            .header("sec-websocket-version", "13")
            .body(Body::empty())
            .expect("valid upgrade-required response");
    }
    let key = match websocket_key(headers) {
        Some(key) => key,
        None => return (StatusCode::BAD_REQUEST, "expected a WebSocket upgrade").into_response(),
    };
    let accept = accept_key(&key);
    let subscription = hub.subscribe(session_id);
    let on_upgrade = hyper::upgrade::on(&mut req);

    tokio::spawn(async move {
        let upgraded = match on_upgrade.await {
            Ok(upgraded) => upgraded,
            Err(err) => {
                tracing::debug!(%err, "websocket upgrade failed");
                return;
            }
        };
        let io = hyper_util::rt::TokioIo::new(upgraded);
        let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(io, Role::Server, None).await;
        match subscription {
            Some(sub) => run_live(ws, sub).await,
            None => send_final(ws, &fallback).await,
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(CONNECTION, "upgrade")
        .header(UPGRADE, "websocket")
        .header("sec-websocket-accept", accept)
        .body(Body::empty())
        .expect("valid switching-protocols response")
}

/// Drive a connected WebSocket against a live scan: send the current state at
/// once (covers a late connect), then a fresh fragment on every tick, answer
/// client pings, and tear down when the scan ends or the client disconnects.
async fn run_live<S>(mut ws: tokio_tungstenite::WebSocketStream<S>, mut sub: Subscription)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if send_progress(&mut ws, &sub).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            biased;
            incoming = ws.next() => match incoming {
                Some(Ok(Message::Ping(payload))) => {
                    if ws.send(Message::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                Some(Ok(_)) => {}
            },
            tick = sub.rx.recv() => match tick {
                Ok(()) => {
                    if send_progress(&mut ws, &sub).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    if send_progress(&mut ws, &sub).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => {
                    // The scan finished; send the terminal fragment and close.
                    let _ = send_progress(&mut ws, &sub).await;
                    break;
                }
            },
        }
    }
    let _ = ws.send(Message::Close(None)).await;
}

/// Render and send the current progress fragment from the live session.
async fn send_progress<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    sub: &Subscription,
) -> Result<(), ()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let snapshot = sub.handle.lock().map_err(|_| ())?.clone();
    let scanner = sub.scanner.lock().map_err(|_| ())?.clone();
    let fragment = view::progress(&snapshot, scanner.as_deref());
    ws.send(Message::Text(fragment.into()))
        .await
        .map_err(|_| ())
}

/// A scan that was already finished when the socket connected: one final fragment.
async fn send_final<S>(mut ws: tokio_tungstenite::WebSocketStream<S>, session: &ScanSession)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let fragment = view::progress(session, None);
    let _ = ws.send(Message::Text(fragment.into())).await;
    let _ = ws.send(Message::Close(None)).await;
}

/// The client's `Sec-WebSocket-Key`, if this is a valid WebSocket upgrade request.
fn websocket_key(headers: &HeaderMap) -> Option<String> {
    let upgrade = headers.get(UPGRADE)?.to_str().ok()?;
    if !upgrade.eq_ignore_ascii_case("websocket") {
        return None;
    }
    headers
        .get("sec-websocket-key")?
        .to_str()
        .ok()
        .map(str::to_string)
}

/// Whether the client offers WebSocket version 13 (RFC 6455 §4.2.1). A header
/// listing several comma-separated versions passes if 13 is among them.
fn version_supported(headers: &HeaderMap) -> bool {
    headers
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|token| token.trim() == "13"))
        .unwrap_or(false)
}

/// Compute `Sec-WebSocket-Accept = base64(sha1(key + GUID))` (RFC 6455).
fn accept_key(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_matches_rfc6455_example() {
        // The canonical example from RFC 6455 §1.3.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn version_supported_requires_13() {
        let mut h = HeaderMap::new();
        assert!(!version_supported(&h), "absent version is rejected");
        h.insert("sec-websocket-version", "8".parse().unwrap());
        assert!(!version_supported(&h), "a non-13 version is rejected");
        h.insert("sec-websocket-version", "13".parse().unwrap());
        assert!(version_supported(&h));
        h.insert("sec-websocket-version", "8, 13".parse().unwrap());
        assert!(version_supported(&h), "13 among several is accepted");
    }

    #[test]
    fn websocket_key_requires_upgrade_header() {
        let mut h = HeaderMap::new();
        h.insert("sec-websocket-key", "abc".parse().unwrap());
        assert_eq!(websocket_key(&h), None, "missing Upgrade header");
        h.insert(UPGRADE, "websocket".parse().unwrap());
        assert_eq!(websocket_key(&h).as_deref(), Some("abc"));
    }

    #[test]
    fn hub_tracks_and_drops_live_scans() {
        let hub = Hub::default();
        let id = Uuid::new_v4();
        let handle = std::sync::Arc::new(std::sync::Mutex::new(ScanSession::new(vec![], vec![])));
        let feed = hub.start(id, handle);
        assert!(hub.subscribe(id).is_some());
        feed.tick("cors");
        hub.finish(id);
        assert!(hub.subscribe(id).is_none(), "finished scans leave the hub");
    }
}
