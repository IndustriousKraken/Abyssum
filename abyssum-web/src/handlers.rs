//! HTTP handlers: pages, HTMX fragments, scan lifecycle, and the WebSocket entry.
//!
//! Handlers are thin: they authenticate (via the gate middleware, which inserts
//! the [`User`]), enforce ownership against the **persisted** owner (never the
//! client), call the shared engine, and render HTML. Visibility is owner-only for
//! a regular user and unrestricted for an admin, exactly as the auth engine's
//! [`visible_session`]/[`visible_sessions`] encode it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use abyssum_core::{
    execute_custom_request, normalize_url, visible_session, visible_sessions, CustomRequestSpec,
    Finding, FindingFilter, ProgressCallback, ProgressUpdate, ScanSession, SessionHandle, Severity,
    Status, Target, User,
};
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Extension;
use serde::Deserialize;
use tokio::net::lookup_host;
use url::Host;
use uuid::Uuid;

use crate::auth;
use crate::state::AppState;
use crate::view;
use crate::ws;

/// Cap on sessions scanned for owner-scoped stats/search, and on rows a search
/// returns. Generous for ordinary use; bounds pathological accounts.
const PAGE: i64 = 200;

// --- Public auth pages -----------------------------------------------------

/// `GET /login` — render the login form (minting a CSRF token if needed).
pub async fn login_page(headers: HeaderMap) -> Response {
    let (csrf, set) = auth::ensure_csrf(&headers);
    auth::html(view::login(&csrf, None), set)
}

/// `POST /login` — verify credentials, set the session cookie, redirect home.
pub async fn login_submit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if !state.login_limiter.check(peer.ip()) {
        return too_many();
    }
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    let username = field(&form, "username").unwrap_or("");
    let password = field(&form, "password").unwrap_or("");
    match state.auth.login(username, password).await {
        Ok(token) => auth::redirect("/", &[auth::session_cookie(&token)]),
        Err(_) => {
            // Non-revealing: the engine returns one error for any bad login.
            let (csrf, set) = auth::ensure_csrf(&headers);
            let body = view::login(&csrf, Some("invalid username or password"));
            with_status(StatusCode::UNAUTHORIZED, auth::html(body, set))
        }
    }
}

/// `GET /register` — render the registration form.
pub async fn register_page(headers: HeaderMap) -> Response {
    let (csrf, set) = auth::ensure_csrf(&headers);
    auth::html(view::register(&csrf, None), set)
}

/// `POST /register` — create an account (first user → admin), redirect to login.
pub async fn register_submit(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> Response {
    if !state.login_limiter.check(peer.ip()) {
        return too_many();
    }
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    let username = field(&form, "username").unwrap_or("");
    let password = field(&form, "password").unwrap_or("");
    if username.is_empty() || password.is_empty() {
        let (csrf, set) = auth::ensure_csrf(&headers);
        let body = view::register(&csrf, Some("username and password are required"));
        return with_status(StatusCode::BAD_REQUEST, auth::html(body, set));
    }
    match state.auth.register(username, password).await {
        Ok(_) => auth::redirect("/login", &[]),
        Err(err) => {
            let (csrf, set) = auth::ensure_csrf(&headers);
            let body = view::register(&csrf, Some(&clean_err(err)));
            with_status(StatusCode::CONFLICT, auth::html(body, set))
        }
    }
}

/// `POST /logout` — invalidate the session and clear the cookie.
pub async fn logout(State(state): State<AppState>, headers: HeaderMap, body: String) -> Response {
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    if let Some(token) = auth::read_cookie(&headers, auth::SESSION_COOKIE) {
        let _ = state.auth.logout(&token).await;
    }
    auth::redirect("/login", &[auth::clear_session_cookie()])
}

// --- Pages -----------------------------------------------------------------

/// `GET /` — the start-scan page.
pub async fn home(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    headers: HeaderMap,
) -> Response {
    let (csrf, set) = auth::ensure_csrf(&headers);
    let scanners = state.orchestrator.registry().available();
    auth::html(view::home(&user, &csrf, &scanners), set)
}

/// `GET /dashboard` — stats + sessions + search shell.
pub async fn dashboard(Extension(user): Extension<User>, headers: HeaderMap) -> Response {
    // Ensure the CSRF cookie exists for the nav's logout form on this page.
    let (_csrf, set) = auth::ensure_csrf(&headers);
    auth::html(view::dashboard(&user), set)
}

/// `GET /custom-requests` — the manual request builder.
pub async fn custom_page(Extension(user): Extension<User>, headers: HeaderMap) -> Response {
    let (csrf, set) = auth::ensure_csrf(&headers);
    auth::html(view::custom_requests(&user, &csrf), set)
}

/// `GET /scan/{id}` — scan-detail page (owner-checked); prefers live state.
pub async fn scan_detail(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    // Authorize against the persisted owner.
    let persisted = match visible_session(&state.db, &user, id).await {
        Ok(session) => session,
        Err(_) => return not_visible(),
    };
    let (_csrf, set) = auth::ensure_csrf(&headers);
    // A live scan's in-memory state is fresher than the (Pending) persisted row.
    let session = state.hub.snapshot(id).unwrap_or(persisted);
    auth::html(view::scan_detail(&user, &session), set)
}

// --- Fragments -------------------------------------------------------------

/// `GET /sessions` — owner-scoped sessions table.
pub async fn sessions_fragment(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
) -> Response {
    match visible_sessions(&state.db, &user, PAGE, 0).await {
        Ok(sessions) => auth::html(view::sessions_table(&sessions, &user), None),
        Err(_) => server_error(),
    }
}

/// `GET /stats` — owner-scoped summary cards.
pub async fn stats_fragment(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
) -> Response {
    let summary = if user.is_admin() {
        state.db.summary(None).await
    } else {
        match owned_session_ids(&state, &user).await {
            Ok(ids) => state.db.summary(Some(&ids)).await,
            Err(_) => return server_error(),
        }
    };
    match summary {
        Ok(summary) => auth::html(view::stats(&summary), None),
        Err(_) => server_error(),
    }
}

/// Query parameters accepted by the findings search fragment.
#[derive(Debug, Default, Deserialize)]
pub struct SearchParams {
    q: Option<String>,
    target: Option<String>,
    scanner: Option<String>,
    level: Option<String>,
    status: Option<String>,
}

/// `GET /findings` — free-text + structured search over the viewer's findings.
pub async fn findings_fragment(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Query(params): Query<SearchParams>,
) -> Response {
    let mut filter = FindingFilter::new().limit(PAGE);
    if let Some(q) = nonempty(params.q.as_deref()) {
        filter = filter.matching(q);
    }
    if let Some(t) = nonempty(params.target.as_deref()) {
        filter = filter.by_target(t);
    }
    if let Some(s) = nonempty(params.scanner.as_deref()) {
        filter = filter.by_scanner(s);
    }
    if let Some(sev) = params.level.as_deref().and_then(parse_severity) {
        filter = filter.by_severity(sev);
    }
    if let Some(st) = params.status.as_deref().and_then(parse_status) {
        filter = filter.by_status(st);
    }

    let findings = if user.is_admin() {
        state.db.search_findings(&filter).await
    } else {
        scoped_search(&state, &user, &filter).await
    };
    match findings {
        Ok(findings) => auth::html(view::findings(&findings), None),
        Err(_) => server_error(),
    }
}

/// `GET /scan/{id}/results` — findings fragment (owner-checked, live-aware).
pub async fn scan_results(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<Uuid>,
) -> Response {
    if visible_session(&state.db, &user, id).await.is_err() {
        return not_visible();
    }
    // A running scan accrues findings in memory; a finished one has them persisted.
    let findings = match state.hub.snapshot(id) {
        Some(session) => session.findings,
        None => match state.db.get_findings(id).await {
            Ok(findings) => findings,
            Err(_) => return server_error(),
        },
    };
    auth::html(view::findings(&findings), None)
}

// --- Scan lifecycle --------------------------------------------------------

/// `POST /scans` — validate, create an owned session, spawn the run, redirect.
pub async fn start_scan(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }

    let target_strs: Vec<&str> = field(&form, "targets")
        .unwrap_or("")
        .split_whitespace()
        .collect();
    let scanner_ids: Vec<String> = form
        .iter()
        .filter(|(k, _)| k == "scanners")
        .map(|(_, v)| v.clone())
        .collect();

    if target_strs.is_empty() {
        return fail_page(StatusCode::BAD_REQUEST, "supply at least one target");
    }
    if scanner_ids.is_empty() {
        return fail_page(StatusCode::BAD_REQUEST, "select at least one scanner");
    }

    let mut targets = Vec::with_capacity(target_strs.len());
    for raw in target_strs {
        match Target::parse(raw) {
            Ok(target) => targets.push(target),
            Err(err) => return fail_page(StatusCode::BAD_REQUEST, &clean_err(err)),
        }
    }

    // create_session validates every scanner id up front (unknown → error, no
    // session created), so an unknown id never issues traffic.
    let handle = match state.orchestrator.create_session(targets, scanner_ids) {
        Ok(handle) => handle,
        Err(err) => return fail_page(StatusCode::BAD_REQUEST, &clean_err(err)),
    };

    let id = {
        let mut session = handle.lock().expect("session not poisoned");
        // Stamp the authenticated creator as the owner before anything persists.
        session.owner_user_id = Some(user.id);
        session.id
    };

    // Persist the owned Pending row first so ownership checks resolve immediately,
    // even before the run finishes (the owner stamp is immutable thereafter).
    let snapshot = handle.lock().expect("session not poisoned").clone();
    if state.db.save_session(&snapshot).await.is_err() {
        return server_error();
    }

    spawn_scan(state.clone(), id, handle);
    auth::redirect(&format!("/scan/{id}"), &[])
}

/// `POST /scan/{id}/cancel` — owner-checked cancel; returns a status fragment.
pub async fn cancel_scan(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    // Owner/admin only — a non-owner is denied and nothing is cancelled.
    if visible_session(&state.db, &user, id).await.is_err() {
        return not_visible();
    }
    // Signal cancellation; an already-finished scan simply has nothing active.
    let _ = state.orchestrator.cancel(id);

    // Reflect the (now cancelling) state plus retained partial findings.
    let session = match state.hub.snapshot(id) {
        Some(session) => session,
        None => match state.db.get_session(id).await {
            Ok(Some(session)) => session,
            _ => return server_error(),
        },
    };
    auth::html(view::progress(&session, None), None)
}

/// `GET /ws/{id}` — live progress WebSocket (owner-checked before upgrade).
pub async fn ws_handler(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<Uuid>,
    req: Request,
) -> Response {
    let session = match visible_session(&state.db, &user, id).await {
        Ok(session) => session,
        Err(_) => return not_visible(),
    };
    ws::upgrade(&state.hub, id, session, req)
}

// --- Custom requests -------------------------------------------------------

/// `POST /custom-requests` — execute one ad-hoc request and render the response.
pub async fn custom_exec(
    State(state): State<AppState>,
    Extension(_user): Extension<User>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    let url = field(&form, "url").unwrap_or("").trim().to_string();
    if url.is_empty() {
        return auth::html(view::error_fragment("a target URL is required"), None);
    }
    // SSRF guard: refuse private/reserved targets unless the operator opted in.
    if let Err(msg) = ssrf_vet(&url, state.config.server.allow_private_custom_targets).await {
        return auth::html(view::error_fragment(&msg), None);
    }
    let method = field(&form, "method").unwrap_or("GET");
    let mut spec = CustomRequestSpec::new(url).method(method);
    if let Some(b) = nonempty(field(&form, "body")) {
        spec = spec.body(b);
    }
    // Auth is additive and optional; absent bearer + cookie ⇒ a keyless request.
    if let Some(token) = nonempty(field(&form, "bearer")) {
        spec = spec.bearer(token);
    }
    if let Some(cookie) = nonempty(field(&form, "cookie")) {
        spec = spec.cookie(cookie);
    }
    for line in field(&form, "headers").unwrap_or("").lines() {
        if let Some((name, value)) = line.split_once(':') {
            let (name, value) = (name.trim(), value.trim());
            if !name.is_empty() {
                spec = spec.header(name, value);
            }
        }
    }

    let outcome = execute_custom_request(&spec, &state.limiter).await;
    auth::html(view::custom_response(&outcome), None)
}

// --- SSRF guard ------------------------------------------------------------

/// Reject a custom-request target that points at a private, loopback, link-local,
/// or otherwise reserved address — an SSRF / lateral-movement guard for the
/// authenticated tool (e.g. cloud metadata at `169.254.169.254`, localhost
/// services, RFC 1918 hosts). Hostnames are resolved and *every* returned address
/// is checked, so a public name that resolves to a private IP is still caught.
/// Skipped entirely when the operator has opted into private targets.
///
/// The URL is normalized exactly as the tool will send it (same scheme-defaulting),
/// so the host vetted here is the host actually contacted.
///
/// ponytail: reqwest re-resolves the name when it connects, so a racing DNS rebind
/// could still slip a private IP past this check. Closing that fully needs pinning
/// the vetted IP via a custom reqwest resolver/connector — add it if this tool is
/// ever exposed to untrusted operators.
async fn ssrf_vet(raw_url: &str, allow_private: bool) -> Result<(), String> {
    if allow_private {
        return Ok(());
    }
    let url = normalize_url(raw_url).map_err(|_| "invalid target URL".to_string())?;
    let blocked = "target resolves to a private or reserved address; set \
                   server.allow_private_custom_targets to allow internal targets"
        .to_string();
    match url.host() {
        Some(Host::Ipv4(ip)) if is_blocked_ip(IpAddr::V4(ip)) => Err(blocked),
        Some(Host::Ipv6(ip)) if is_blocked_ip(IpAddr::V6(ip)) => Err(blocked),
        Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) => Ok(()),
        Some(Host::Domain(name)) => {
            if name.eq_ignore_ascii_case("localhost") {
                return Err(blocked);
            }
            let port = url.port_or_known_default().unwrap_or(0);
            let addrs = lookup_host((name, port))
                .await
                .map_err(|_| "could not resolve target host".to_string())?;
            let mut resolved = false;
            for addr in addrs {
                resolved = true;
                if is_blocked_ip(addr.ip()) {
                    return Err(blocked);
                }
            }
            if resolved {
                Ok(())
            } else {
                Err("could not resolve target host".to_string())
            }
        }
        None => Err("target URL has no host".to_string()),
    }
}

/// Whether `ip` falls in a private, loopback, link-local, or otherwise reserved
/// range the custom-requests tool must not reach by default. Covers RFC 1918,
/// carrier-grade NAT, link-local, loopback, unspecified, broadcast, and TEST-NET,
/// plus IPv6 loopback/unspecified and unique-/link-local; an IPv4-mapped IPv6
/// address is unwrapped and re-checked.
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                // 100.64.0.0/10 carrier-grade NAT (`Ipv4Addr::is_shared` is unstable).
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 0x40)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ip(IpAddr::V4(v4));
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        }
    }
}

// --- Background execution --------------------------------------------------

/// Register a live feed and run the scan to completion in the background,
/// persisting the final session and its findings (partial on cancel) so they
/// remain viewable, then retire the feed.
fn spawn_scan(state: AppState, id: Uuid, handle: SessionHandle) {
    let feed = state.hub.start(id, handle);
    tokio::spawn(async move {
        let feed_cb = feed.clone();
        let callback: ProgressCallback = Arc::new(move |update: ProgressUpdate| {
            feed_cb.tick(&update.scanner_id);
        });

        match state.orchestrator.run(id, Some(callback)).await {
            Ok(session) => {
                if let Err(err) = persist_results(&state, &session).await {
                    tracing::error!(%err, %id, "failed to persist scan results");
                }
            }
            Err(err) => tracing::error!(%err, %id, "scan run failed"),
        }

        // Push the terminal state to any watcher, then drop the feed so the
        // WebSocket stream closes.
        feed.wake();
        state.hub.finish(id);
    });
}

/// Persist a finished session's metadata and findings (the run leaves the
/// session terminal in memory; this is the durable copy the UI reads afterward).
async fn persist_results(state: &AppState, session: &ScanSession) -> abyssum_core::Result<()> {
    state.db.save_session(session).await?;
    for finding in &session.findings {
        state.db.save_finding(session.id, finding).await?;
    }
    Ok(())
}

// --- Owner-scoping helpers -------------------------------------------------

/// The ids of every session a non-admin viewer owns (bounded by [`PAGE`]).
async fn owned_session_ids(state: &AppState, user: &User) -> abyssum_core::Result<Vec<Uuid>> {
    let sessions = state.db.list_sessions_owned_by(user.id, PAGE, 0).await?;
    Ok(sessions.iter().map(|s| s.id).collect())
}

/// Run a finding search restricted to a non-admin viewer's own sessions: apply
/// the filter per owned session, then merge newest-first and cap at [`PAGE`].
async fn scoped_search(
    state: &AppState,
    user: &User,
    filter: &FindingFilter,
) -> abyssum_core::Result<Vec<Finding>> {
    let ids = owned_session_ids(state, user).await?;
    let mut all = Vec::new();
    for id in ids {
        let scoped = filter.clone().by_session(id);
        all.extend(state.db.search_findings(&scoped).await?);
    }
    all.sort_by_key(|f| std::cmp::Reverse(f.timestamp));
    all.truncate(PAGE as usize);
    Ok(all)
}

// --- Response + parsing helpers --------------------------------------------

/// `403 Forbidden` for a failed CSRF check.
fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "forbidden").into_response()
}

/// `429 Too Many Requests` for an IP that has exceeded the auth-attempt rate.
fn too_many() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        "too many attempts; try again shortly",
    )
        .into_response()
}

/// A session the viewer may not see — and one that does not exist — both yield
/// the same `404`, disclosing nothing about another user's sessions.
fn not_visible() -> Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// `500` for an unexpected persistence failure.
fn server_error() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

/// A minimal full-page error (used by the full-page scan-start form).
fn fail_page(status: StatusCode, message: &str) -> Response {
    let body = view::page(
        "Error",
        None,
        &format!(
            "{}<p><a href=\"/\">Back to start</a></p>",
            view::error_fragment(message)
        ),
    );
    with_status(status, Html(body).into_response())
}

/// Override a response's status while keeping its headers and body.
fn with_status(status: StatusCode, mut resp: Response) -> Response {
    *resp.status_mut() = status;
    resp
}

/// Strip the `Error` variant's prefix so the user sees the message, not the
/// Rust error category.
fn clean_err(err: abyssum_core::Error) -> String {
    let text = err.to_string();
    text.split_once(": ")
        .map(|(_, rest)| rest.to_string())
        .unwrap_or(text)
}

/// Parse an `application/x-www-form-urlencoded` body into ordered key/value pairs,
/// preserving repeated keys (e.g. `scanners`). A tiny decoder beats fighting
/// `serde_urlencoded`, which collapses repeated keys.
fn parse_form(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(k), percent_decode(v))
        })
        .collect()
}

/// Decode one `application/x-www-form-urlencoded` component (`+` → space, `%XX`).
fn percent_decode(input: &str) -> String {
    let spaced = input.replace('+', " ");
    let bytes = spaced.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// The first value for `name` in a parsed form.
fn field<'a>(form: &'a [(String, String)], name: &str) -> Option<&'a str> {
    form.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Trim a value, returning `None` if it is empty.
fn nonempty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn parse_severity(text: &str) -> Option<Severity> {
    match text.trim().to_ascii_lowercase().as_str() {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

fn parse_status(text: &str) -> Option<Status> {
    match text.trim().to_ascii_lowercase().as_str() {
        "vulnerable" => Some(Status::Vulnerable),
        "safe" => Some(Status::Safe),
        "info" => Some(Status::Info),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_form_keeps_repeated_keys_and_decodes() {
        let form = parse_form("scanners=cors&scanners=bac&targets=https%3A%2F%2Fa.test+b");
        let scanners: Vec<&str> = form
            .iter()
            .filter(|(k, _)| k == "scanners")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(scanners, vec!["cors", "bac"]);
        assert_eq!(field(&form, "targets"), Some("https://a.test b"));
    }

    #[test]
    fn percent_decode_handles_trailing_and_invalid_escapes() {
        assert_eq!(percent_decode("a%2"), "a%2"); // truncated escape left as-is
        assert_eq!(percent_decode("a%zz"), "a%zz"); // non-hex left as-is
        assert_eq!(percent_decode("%41%42"), "AB");
    }

    #[test]
    fn nonempty_trims_and_drops_blank() {
        assert_eq!(nonempty(Some("  x ")).as_deref(), Some("x"));
        assert_eq!(nonempty(Some("   ")), None);
        assert_eq!(nonempty(None), None);
    }

    #[test]
    fn is_blocked_ip_rejects_private_reserved_allows_public() {
        let blk = |s: &str| is_blocked_ip(s.parse().unwrap());
        // Private / loopback / link-local / reserved / cloud-metadata / CGNAT.
        assert!(blk("127.0.0.1"));
        assert!(blk("10.0.0.5"));
        assert!(blk("192.168.1.1"));
        assert!(blk("172.16.0.1"));
        assert!(blk("169.254.169.254"));
        assert!(blk("100.64.0.1"));
        assert!(blk("0.0.0.0"));
        assert!(blk("::1"));
        assert!(blk("fc00::1"));
        assert!(blk("fe80::1"));
        assert!(blk("::ffff:127.0.0.1")); // IPv4-mapped loopback
                                          // Public addresses are allowed through.
        assert!(!blk("8.8.8.8"));
        assert!(!blk("1.1.1.1"));
        assert!(!blk("2606:4700:4700::1111"));
    }

    #[test]
    fn ssrf_vet_allows_when_opted_in_and_blocks_loopback() {
        // Opt-in bypasses the guard entirely.
        let rt = tokio::runtime::Runtime::new().unwrap();
        assert!(rt.block_on(ssrf_vet("http://127.0.0.1/", true)).is_ok());
        // Default policy blocks an IP-literal loopback and the `localhost` name.
        assert!(rt.block_on(ssrf_vet("http://127.0.0.1/", false)).is_err());
        assert!(rt.block_on(ssrf_vet("http://localhost/", false)).is_err());
        // A public host passes the literal/name checks.
        assert!(rt.block_on(ssrf_vet("https://1.1.1.1/", false)).is_ok());
    }

    #[test]
    fn severity_and_status_parse_known_values_only() {
        assert_eq!(parse_severity("HIGH"), Some(Severity::High));
        assert_eq!(parse_severity("bogus"), None);
        assert_eq!(parse_status("vulnerable"), Some(Status::Vulnerable));
        assert_eq!(parse_status(""), None);
    }
}
