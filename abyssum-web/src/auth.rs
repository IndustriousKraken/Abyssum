//! The authentication gate, cookies, and CSRF — the surface's trust boundary.
//!
//! Identity comes from the `add-authentication` engine ([`AuthManager`]): a
//! session token carried in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie,
//! resolved to a [`User`] by middleware that inserts it into request extensions
//! for handlers to enforce ownership against. State-changing POSTs additionally
//! carry a double-submit CSRF token (a non-`HttpOnly` `csrf` cookie echoed in a
//! form field), validated constant-time on submit.

use abyssum_core::User;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use rand::RngCore;

use crate::state::AppState;

/// The opaque session-token cookie (`HttpOnly`, `Secure`, `SameSite=Lax`).
pub const SESSION_COOKIE: &str = "abyssum_session";
/// The double-submit CSRF cookie. Readable by same-origin JS (not `HttpOnly`) so
/// the nav's logout/cancel forms can echo it; cross-origin pages cannot read it.
pub const CSRF_COOKIE: &str = "csrf";

// --- Cookies ---------------------------------------------------------------

/// Read a named cookie value from the request's `Cookie` header.
pub fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get("cookie")?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// The `Set-Cookie` value that establishes a login session.
pub fn session_cookie(token: &str) -> String {
    format!("{SESSION_COOKIE}={token}; HttpOnly; Secure; SameSite=Lax; Path=/")
}

/// The `Set-Cookie` value that clears the login session on logout.
pub fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
}

/// The `Set-Cookie` value for the CSRF token.
fn csrf_cookie(token: &str) -> String {
    format!("{CSRF_COOKIE}={token}; Secure; SameSite=Lax; Path=/")
}

// --- CSRF (double-submit) --------------------------------------------------

/// Resolve the CSRF token for a page render: reuse the incoming `csrf` cookie, or
/// mint a fresh one. Returns the token and, when freshly minted, the `Set-Cookie`
/// value to attach to the response.
pub fn ensure_csrf(headers: &HeaderMap) -> (String, Option<String>) {
    match read_cookie(headers, CSRF_COOKIE) {
        Some(token) if !token.is_empty() => (token, None),
        _ => {
            let token = random_token();
            let set = csrf_cookie(&token);
            (token, Some(set))
        }
    }
}

/// Validate a submitted CSRF token against the `csrf` cookie (constant-time). A
/// missing cookie or field, or a mismatch, fails closed.
pub fn verify_csrf(headers: &HeaderMap, submitted: Option<&str>) -> bool {
    match (read_cookie(headers, CSRF_COOKIE), submitted) {
        (Some(cookie), Some(field)) if !cookie.is_empty() => {
            ct_eq(cookie.as_bytes(), field.as_bytes())
        }
        _ => false,
    }
}

/// A fresh high-entropy token (32 CSPRNG bytes, hex), for sessions handled by the
/// engine and the CSRF cookie minted here.
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(64);
    use std::fmt::Write;
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Constant-time byte comparison (no early return on the first differing byte).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// --- Responses -------------------------------------------------------------

/// An HTML response, optionally attaching a freshly-minted CSRF `Set-Cookie`.
pub fn html(body: String, set_cookie: Option<String>) -> Response {
    let mut resp = Html(body).into_response();
    if let Some(set) = set_cookie {
        if let Ok(value) = set.parse() {
            resp.headers_mut().append(SET_COOKIE, value);
        }
    }
    resp
}

/// A `303 See Other` redirect, attaching any `Set-Cookie` values (session set/clear).
pub fn redirect(location: &str, cookies: &[String]) -> Response {
    let mut builder = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(LOCATION, location);
    for cookie in cookies {
        builder = builder.header(SET_COOKIE, cookie);
    }
    builder
        .body(Body::empty())
        .expect("valid redirect response")
}

// --- Middleware ------------------------------------------------------------

/// Resolve the authenticated user from the session cookie, or `None`.
pub async fn current_user(state: &AppState, headers: &HeaderMap) -> Option<User> {
    let token = read_cookie(headers, SESSION_COOKIE)?;
    state.auth.guard(Some(&token)).await.ok()
}

/// Page-route gate: serve when authenticated, redirect to `/login` otherwise.
pub async fn require_user_page(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    match current_user(&state, req.headers()).await {
        Some(user) => {
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        None => redirect("/login", &[]),
    }
}

/// Data/WebSocket gate: serve when authenticated, reject `401` otherwise.
pub async fn require_user_data(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    match current_user(&state, req.headers()).await {
        Some(user) => {
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        None => (StatusCode::UNAUTHORIZED, "authentication required").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_named_cookie_among_several() {
        let mut h = HeaderMap::new();
        h.insert(
            "cookie",
            "a=1; abyssum_session=tok; csrf=xyz".parse().unwrap(),
        );
        assert_eq!(read_cookie(&h, SESSION_COOKIE).as_deref(), Some("tok"));
        assert_eq!(read_cookie(&h, CSRF_COOKIE).as_deref(), Some("xyz"));
        assert_eq!(read_cookie(&h, "missing"), None);
    }

    #[test]
    fn csrf_verifies_only_on_cookie_field_match() {
        let mut h = HeaderMap::new();
        h.insert("cookie", "csrf=secret".parse().unwrap());
        assert!(verify_csrf(&h, Some("secret")));
        assert!(!verify_csrf(&h, Some("other")));
        assert!(!verify_csrf(&h, None));
        // No cookie at all -> rejected.
        assert!(!verify_csrf(&HeaderMap::new(), Some("secret")));
    }

    #[test]
    fn ensure_csrf_reuses_then_mints() {
        let mut h = HeaderMap::new();
        h.insert("cookie", "csrf=keep".parse().unwrap());
        let (token, set) = ensure_csrf(&h);
        assert_eq!(token, "keep");
        assert!(set.is_none(), "an existing token is reused, not reset");

        let (fresh, set) = ensure_csrf(&HeaderMap::new());
        assert_eq!(fresh.len(), 64);
        assert!(set.unwrap().contains("csrf="));
    }

    #[test]
    fn tokens_are_unique_hex() {
        let a = random_token();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, random_token());
    }
}
