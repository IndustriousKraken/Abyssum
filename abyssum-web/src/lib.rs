//! `abyssum-web` — the authenticated web surface over the shared scan engine.
//!
//! This crate is deliberately thin: it translates HTTP/WebSocket traffic to and
//! from `abyssum-core` (orchestration, persistence, auth, the custom-requests
//! tool), behind the authentication gate the canon requires. All scanning,
//! storage, and auth logic lives in core; here we only build a router, render
//! server-side HTML + HTMX fragments, and fan live progress out over per-session
//! WebSockets.
//!
//! - [`state`] — [`AppState`], the router, and the bind/serve path.
//! - [`auth`] — the session gate, cookies, and CSRF.
//! - [`handlers`] — page, fragment, scan-lifecycle, and WebSocket handlers.
//! - [`ws`] — the live-progress hub and the hand-driven WebSocket upgrade.
//! - [`view`] — server-rendered HTML and HTMX fragments.

pub mod auth;
pub mod handlers;
pub mod state;
pub mod view;
pub mod ws;

pub use state::{build_router, default_static_dir, serve, AppState};
