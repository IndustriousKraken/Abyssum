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
    CustomRequestSpec, Finding, FindingFilter, FindingId, PacingPolicy, ProgressCallback,
    ProgressUpdate, ScanOptions, ScanSession, SessionHandle, Severity, Status,
    TIMING_POLICY_OPTION, TagApply, Target, User, execute_custom_request, normalize_url,
    visible_session, visible_sessions,
};
use abyssum_scanners::WORDLIST_OPTION;
use axum::Extension;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::header::{
    CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use base64::Engine;
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

/// `GET /scan` — the start-scan page.
pub async fn scan_page(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    headers: HeaderMap,
) -> Response {
    let (csrf, set) = auth::ensure_csrf(&headers);
    let scanners = state.orchestrator.registry().available();
    // The user's own timing profiles + custom wordlists populate the pacing and
    // wordlist selectors (both private to them).
    let profiles = state
        .timing
        .list_for_user(user.id)
        .await
        .unwrap_or_default();
    let wordlists = state
        .wordlists
        .list_for_user(user.id)
        .await
        .unwrap_or_default();
    // The user's authorized engagements populate the optional engagement selector.
    let engagements = state
        .engagements
        .list_for_user(&user)
        .await
        .unwrap_or_default();
    auth::html(
        view::scan_page(&user, &csrf, &scanners, &profiles, &wordlists, &engagements),
        set,
    )
}

/// `GET /` and `GET /dashboard` — stats + sessions + search shell; the default
/// post-login landing page.
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
    let (csrf, set) = auth::ensure_csrf(&headers);
    // A live scan's in-memory state is fresher than the (Pending) persisted row.
    let session = state.hub.snapshot(id).unwrap_or(persisted);
    // The user's authorized engagements populate the "assign to engagement" form.
    let engagements = state
        .engagements
        .list_for_user(&user)
        .await
        .unwrap_or_default();
    auth::html(view::scan_detail(&user, &csrf, &session, &engagements), set)
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
        Ok(findings) => auth::html(view::findings(&findings, None), None),
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
    auth::html(view::findings(&findings, Some(id)), None)
}

/// `POST /scan/{id}/findings/{fid}/analyze` — best-effort AI analysis of one
/// finding (owner-checked). Renders the model's analysis, or a clear notice in
/// place on any non-fatal failure (disabled, unconfigured, or a provider error).
/// Never aborts: the engine call returns a displayable message, not a panic.
pub async fn analyze_finding(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path((id, fid)): Path<(Uuid, FindingId)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    // Owner/admin only — authorize against the persisted owner, never the client.
    if visible_session(&state.db, &user, id).await.is_err() {
        return not_visible();
    }
    // Pull the finding from this session (live snapshot first, else persisted).
    let finding = match find_in_session(&state, id, fid).await {
        Some(finding) => finding,
        None => return auth::html(view::error_fragment("finding not found"), None),
    };

    match abyssum_core::analyze_finding(&state.config.ai, &finding).await {
        Ok(analysis) => auth::html(view::ai_analysis(&analysis), None),
        // A non-fatal failure (disabled, unconfigured, provider error, timeout) is
        // shown as a notice in place — the finding and view are left unchanged.
        Err(err) => auth::html(view::error_fragment(&clean_err(err)), None),
    }
}

/// Find one finding by id within a session the caller has already been authorized
/// for: a live run accrues findings in memory, a finished one has them persisted.
async fn find_in_session(state: &AppState, id: Uuid, fid: FindingId) -> Option<Finding> {
    let findings = match state.hub.snapshot(id) {
        Some(session) => session.findings,
        None => state.db.get_findings(id).await.ok()?,
    };
    findings.into_iter().find(|f| f.id == Some(fid))
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

    // Per-scan option inputs are namespaced under `opt.<key>` on the scan form;
    // collect any present so the scan carries them.
    let mut options = scan_options_from_form(&form);

    // Resolve the selected timing profile (a profile id under `opt.timing_profile`)
    // to the concrete pacing policy the engine draws from, recorded under the
    // reserved option key the orchestrator reads (g05). The lookup is owner-scoped,
    // so a user can only ever select one of their own profiles; a blank or unknown
    // selection leaves the conservative default in force.
    if let Some(selection) = options
        .get("timing_profile")
        .map(str::trim)
        .map(str::to_string)
        && let Ok(id) = selection.parse::<i64>()
        && let Ok(Some(profile)) = state.timing.get_for_user(user.id, id).await
        && let Ok(json) = serde_json::to_string(&profile.policy)
    {
        options.set(TIMING_POLICY_OPTION, json);
    }

    // Owner-scope the selected custom wordlist (g07): the scan form carries the
    // chosen list's id under `opt.wordlist`, but the scanner trusts it, so keep it
    // ONLY when it names one of this user's own lists. A missing, non-numeric, or
    // foreign id is stripped, leaving the seeded default in force — a crafted id can
    // never select (or read) another operator's list.
    let wordlist_ok = match options
        .get(WORDLIST_OPTION)
        .and_then(|v| v.trim().parse::<i64>().ok())
    {
        Some(id) => matches!(state.wordlists.get_for_user(user.id, id).await, Ok(Some(_))),
        None => false,
    };
    if !wordlist_ok {
        options.remove(WORDLIST_OPTION);
    }

    // create_session_with_options validates every scanner id up front (unknown →
    // error, no session created), so an unknown id never issues traffic.
    let handle = match state
        .orchestrator
        .create_session_with_options(targets, scanner_ids, options)
    {
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

    // Optional engagement association chosen on the form. Best-effort: the store
    // owner-scopes it, so a blank, non-numeric, or foreign id simply leaves the
    // scan unassociated — it never blocks or alters the run (scope is reference
    // material only). Requires the Pending row above so the session is visible.
    if let Some(eid) = field(&form, "engagement").and_then(|v| v.trim().parse::<i64>().ok()) {
        let _ = state.engagements.assign_session(&user, Some(eid), id).await;
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

// --- Timing profiles -------------------------------------------------------

/// `GET /timing-profiles` — the user's reusable pacing profiles plus a form to
/// add a new one or adjust an existing one. Private to the user (owner-scoped).
pub async fn timing_profiles_page(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    headers: HeaderMap,
) -> Response {
    let (csrf, set) = auth::ensure_csrf(&headers);
    let profiles = state
        .timing
        .list_for_user(user.id)
        .await
        .unwrap_or_default();
    auth::html(view::timing_profiles_page(&user, &csrf, &profiles), set)
}

/// `POST /timing-profiles` — create a new profile owned by the authenticated user.
pub async fn create_timing_profile(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    let name = field(&form, "name").unwrap_or("").to_string();
    let policy = match policy_from_form(&form) {
        Ok(policy) => policy,
        Err(msg) => return fail_page(StatusCode::BAD_REQUEST, &msg),
    };
    match state.timing.create(user.id, &name, &policy).await {
        Ok(_) => auth::redirect("/timing-profiles", &[]),
        Err(err) => fail_page(StatusCode::BAD_REQUEST, &clean_err(err)),
    }
}

/// `POST /timing-profiles/{id}` — adjust one of the user's profiles (owner-scoped:
/// a profile the user does not own is treated as not found).
pub async fn update_timing_profile(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    let name = field(&form, "name").unwrap_or("").to_string();
    let policy = match policy_from_form(&form) {
        Ok(policy) => policy,
        Err(msg) => return fail_page(StatusCode::BAD_REQUEST, &msg),
    };
    match state.timing.update(user.id, id, &name, &policy).await {
        Ok(_) => auth::redirect("/timing-profiles", &[]),
        Err(err) => fail_page(StatusCode::BAD_REQUEST, &clean_err(err)),
    }
}

// --- Custom wordlists ------------------------------------------------------

/// A sane ceiling on one wordlist import's request body (name + CSRF + the pasted
/// or uploaded text), rejected before parsing so a huge upload cannot exhaust
/// memory. Comfortably holds a serious recon list (tens of thousands of lines).
const MAX_WORDLIST_IMPORT_BYTES: usize = 1024 * 1024;

/// `GET /wordlists` — the user's custom wordlists plus an import form (paste or
/// `.txt` upload). Private to the user (owner-scoped).
pub async fn wordlists_page(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    headers: HeaderMap,
) -> Response {
    render_wordlists(&state, &user, &headers, None).await
}

/// `POST /wordlists` — import a wordlist owned by the authenticated user, from
/// pasted text or an uploaded `.txt` file (both arrive as the `text` field; the
/// browser reads a chosen file into it client-side). The import is normalized and
/// the result reported on the re-rendered page rather than imported silently.
pub async fn import_wordlist(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    headers: HeaderMap,
    body: String,
) -> Response {
    // Enforce the size ceiling before doing any work on the body.
    if body.len() > MAX_WORDLIST_IMPORT_BYTES {
        return fail_page(
            StatusCode::PAYLOAD_TOO_LARGE,
            "wordlist upload is too large (max 1 MiB)",
        );
    }
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    let name = field(&form, "name").unwrap_or("").to_string();
    let text = field(&form, "text").unwrap_or("").to_string();

    let notice = match state.wordlists.import(user.id, &name, &text).await {
        Ok((list, report)) => format!(
            "Imported \"{}\": {} entries stored, {} dropped \
             ({} duplicates, {} blank, {} comments).",
            list.name,
            report.imported,
            report.dropped(),
            report.dropped_duplicate,
            report.dropped_blank,
            report.dropped_comment,
        ),
        Err(err) => format!("Import failed: {}", clean_err(err)),
    };
    render_wordlists(&state, &user, &headers, Some(notice)).await
}

/// Render the wordlists page for `user`, listing their lists and (optionally)
/// surfacing an import notice. Shared by the GET page and the POST import result.
async fn render_wordlists(
    state: &AppState,
    user: &User,
    headers: &HeaderMap,
    notice: Option<String>,
) -> Response {
    let (csrf, set) = auth::ensure_csrf(headers);
    let lists = state
        .wordlists
        .list_for_user(user.id)
        .await
        .unwrap_or_default();
    auth::html(
        view::wordlists_page(user, &csrf, &lists, notice.as_deref()),
        set,
    )
}

/// Ceiling on a user-entered pacing delay: one day. Well beyond any realistic
/// stealth pacing, but bounded so a finite-but-huge value (e.g. `1e300`) can never
/// be stored and later overflow `Duration` when the profile paces its first request.
const MAX_DELAY_SECS: f64 = 86_400.0;

/// Build a [`PacingPolicy`] from the management form's `shape` + `min` + `max`
/// fields. `organic` yields a heavy-tailed shape sized from the window; anything
/// else a uniform window. Non-numeric, negative, or out-of-range delays are rejected.
fn policy_from_form(form: &[(String, String)]) -> Result<PacingPolicy, String> {
    let parse = |name: &str| -> Result<f64, String> {
        let raw = field(form, name).unwrap_or("").trim().to_string();
        let value: f64 = raw
            .parse()
            .map_err(|_| format!("{name} must be a number of seconds"))?;
        // `contains` also rejects NaN and infinity (neither is in the range).
        if !(0.0..=MAX_DELAY_SECS).contains(&value) {
            return Err(format!(
                "{name} must be a number of seconds between 0 and {MAX_DELAY_SECS}"
            ));
        }
        Ok(value)
    };
    let min = parse("min")?;
    let max = parse("max")?;
    Ok(match field(form, "shape") {
        Some("organic") => PacingPolicy::organic(min, max),
        _ => PacingPolicy::uniform(min, max),
    })
}

// --- Engagements -----------------------------------------------------------

/// `GET /engagements` — the operator's authorized engagements plus a create form
/// (admin sees all). Private to the authorized set.
pub async fn engagements_page(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    headers: HeaderMap,
) -> Response {
    let (csrf, set) = auth::ensure_csrf(&headers);
    let engagements = state
        .engagements
        .list_for_user(&user)
        .await
        .unwrap_or_default();
    auth::html(view::engagements_page(&user, &csrf, &engagements), set)
}

/// `POST /engagements` — create an engagement owned by the authenticated operator.
pub async fn create_engagement(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    let name = field(&form, "name").unwrap_or("");
    match state.engagements.create(&user, name).await {
        Ok(engagement) => auth::redirect(&format!("/engagements/{}", engagement.id), &[]),
        Err(err) => fail_page(StatusCode::BAD_REQUEST, &clean_err(err)),
    }
}

/// `GET /engagements/{id}` — one engagement: its associated scans and attached
/// documents (owner/authorized-checked; a non-authorized viewer gets a 404).
pub async fn engagement_detail(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<i64>,
    headers: HeaderMap,
) -> Response {
    render_engagement_detail(&state, &user, id, &headers, None).await
}

/// A sane ceiling on how many extra bytes a document request body may carry beyond
/// the decoded document itself (base64 inflation ≈ ×1.34 plus urlencoding), added
/// to twice the configured max so the *store* — not this guard — reports an
/// oversized document with a clear message.
const DOCUMENT_BODY_SLACK: usize = 64 * 1024;

/// `POST /engagements/{id}/documents` — attach a scope/authorization document:
/// pasted text (`kind=text`), an external URL (`kind=url`), or an uploaded file
/// (`kind=file`, its bytes base64/data-URL-encoded in `file_data`). Owner-scoped;
/// the store rejects an oversized or disallowed upload without storing it.
pub async fn attach_document(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<i64>,
    headers: HeaderMap,
    body: String,
) -> Response {
    // Reject an absurd body before parsing. The real document-size bound is the
    // configured `max_document_bytes`, enforced by the store on the decoded bytes.
    let body_cap = state
        .config
        .server
        .max_document_bytes
        .saturating_mul(2)
        .saturating_add(DOCUMENT_BODY_SLACK);
    if body.len() > body_cap {
        return fail_page(
            StatusCode::PAYLOAD_TOO_LARGE,
            "document upload is too large",
        );
    }
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }

    let kind = field(&form, "kind").unwrap_or("text");
    let result = match kind {
        "url" => {
            let url = field(&form, "url").unwrap_or("");
            state.engagements.attach_url(&user, id, url).await
        }
        "file" => match decode_upload(field(&form, "file_data").unwrap_or("")) {
            Ok(bytes) => {
                let filename = field(&form, "file_name").unwrap_or("document");
                state
                    .engagements
                    .attach_file(
                        &user,
                        id,
                        filename,
                        &bytes,
                        state.config.server.max_document_bytes,
                    )
                    .await
            }
            Err(msg) => Err(abyssum_core::Error::Other(msg)),
        },
        // Default (and explicit "text"): pasted scope text.
        _ => {
            let content = field(&form, "content").unwrap_or("");
            state.engagements.attach_text(&user, id, content).await
        }
    };

    match result {
        Ok(_) => auth::redirect(&format!("/engagements/{id}"), &[]),
        // An authorization/visibility failure discloses nothing (404); a validation
        // error (empty, oversized, disallowed type, bad URL) re-renders in place.
        Err(abyssum_core::Error::Auth(_)) => not_visible(),
        Err(err) => {
            render_engagement_detail(&state, &user, id, &headers, Some(clean_err(err))).await
        }
    }
}

/// `GET /engagements/{id}/documents/{doc_id}` — serve an uploaded document's bytes
/// **safely**: with the content type the engine detected from the bytes (never the
/// client's claim, never `text/html`), sniffing disabled, a `Content-Disposition`,
/// and a strict `sandbox` CSP that also allows same-origin framing so a PDF renders
/// inline via the browser's native viewer. A viewer who may not see it gets a 404.
pub async fn serve_document(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path((id, doc_id)): Path<(i64, i64)>,
) -> Response {
    let blob = match state.engagements.document_blob(&user, id, doc_id).await {
        Ok(blob) => blob,
        Err(_) => return not_visible(),
    };
    // ponytail: `sandbox` gives the strongest isolation and modern browsers still
    // render a PDF under it; the content-type + nosniff already stop the bytes
    // executing as page content, so drop `sandbox` only if a browser's native PDF
    // viewer ever fails to render inline under it.
    Response::builder()
        .header(CONTENT_TYPE, blob.content_type)
        .header(X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(
            CONTENT_DISPOSITION,
            format!("inline; filename=\"{}\"", blob.filename),
        )
        .header(
            CONTENT_SECURITY_POLICY,
            "default-src 'none'; frame-ancestors 'self'; sandbox",
        )
        .header(X_FRAME_OPTIONS, "SAMEORIGIN")
        .body(Body::from(blob.bytes))
        .unwrap_or_else(|_| server_error())
}

/// `POST /scan/{id}/assign` — associate an existing scan with an engagement (or
/// clear its association when the field is blank). Both the scan and the chosen
/// engagement must be visible to the operator; the store records who assigned it.
pub async fn assign_scan(
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
    // A blank selection clears the association; otherwise a numeric engagement id.
    let engagement = field(&form, "engagement")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<i64>().ok());
    match state
        .engagements
        .assign_session(&user, engagement, id)
        .await
    {
        Ok(()) => auth::redirect(&format!("/scan/{id}"), &[]),
        Err(_) => not_visible(),
    }
}

/// Render an engagement's detail page (its scans + documents), optionally with a
/// notice from a failed document attach. Shared by the GET route and the attach
/// error path. A viewer who may not see the engagement gets a 404.
async fn render_engagement_detail(
    state: &AppState,
    user: &User,
    id: i64,
    headers: &HeaderMap,
    notice: Option<String>,
) -> Response {
    let engagement = match state.engagements.get_for_user(user, id).await {
        Ok(engagement) => engagement,
        Err(_) => return not_visible(),
    };
    let (csrf, set) = auth::ensure_csrf(headers);
    let sessions = state
        .engagements
        .sessions_for_engagement(user, id)
        .await
        .unwrap_or_default();
    let documents = state
        .engagements
        .documents(user, id)
        .await
        .unwrap_or_default();
    auth::html(
        view::engagement_detail(
            user,
            &csrf,
            &engagement,
            &sessions,
            &documents,
            notice.as_deref(),
        ),
        set,
    )
}

/// Decode an uploaded file field into raw bytes. The browser submits the file as a
/// base64 data URL (`data:<type>;base64,<payload>`) read client-side; a bare base64
/// payload is accepted too. The declared type in the prefix is ignored — the store
/// detects the real type from the decoded bytes.
fn decode_upload(field_value: &str) -> Result<Vec<u8>, String> {
    let value = field_value.trim();
    if value.is_empty() {
        return Err("no file was selected".to_string());
    }
    // Strip an optional `data:...,` prefix, keeping only the base64 payload.
    let payload = match value.split_once(',') {
        Some((prefix, rest)) if prefix.starts_with("data:") => rest,
        _ => value,
    };
    base64::engine::general_purpose::STANDARD
        .decode(payload.trim())
        .map_err(|_| "the uploaded file could not be decoded".to_string())
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

// --- Annotations: notes ----------------------------------------------------

/// `GET /scan/{id}/notes` — the session's notes fragment (owner-checked).
pub async fn session_notes_fragment(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<Uuid>,
) -> Response {
    render_session_notes(&state, &user, id).await
}

/// `POST /scan/{id}/notes` — add a session-level note; returns the notes fragment.
pub async fn add_session_note(
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
    let content = field(&form, "content").unwrap_or("");
    match state.annotations.add_note(&user, id, None, content).await {
        Ok(_) => render_session_notes(&state, &user, id).await,
        Err(err) => annotate_err(err),
    }
}

/// `GET /scan/{id}/findings/{fid}/notes` — a finding's notes fragment.
pub async fn finding_notes_fragment(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path((id, fid)): Path<(Uuid, FindingId)>,
) -> Response {
    render_finding_notes(&state, &user, id, fid).await
}

/// `POST /scan/{id}/findings/{fid}/notes` — add a finding-level note.
pub async fn add_finding_note(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path((id, fid)): Path<(Uuid, FindingId)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    let content = field(&form, "content").unwrap_or("");
    match state
        .annotations
        .add_note(&user, id, Some(fid), content)
        .await
    {
        Ok(_) => render_finding_notes(&state, &user, id, fid).await,
        Err(err) => annotate_err(err),
    }
}

/// `POST /notes/{note_id}/edit` — edit a note; re-renders its scope's fragment.
pub async fn edit_note(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(note_id): Path<i64>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    let content = field(&form, "content").unwrap_or("");
    match state.annotations.edit_note(&user, note_id, content).await {
        Ok(note) => render_note_scope(&state, &user, note.session_id, note.finding_id).await,
        Err(err) => annotate_err(err),
    }
}

/// `POST /notes/{note_id}/delete` — delete a note; re-renders its scope's fragment.
pub async fn delete_note(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(note_id): Path<i64>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    match state.annotations.delete_note(&user, note_id).await {
        Ok(note) => render_note_scope(&state, &user, note.session_id, note.finding_id).await,
        Err(err) => annotate_err(err),
    }
}

// --- Annotations: tags -----------------------------------------------------

/// `GET /tags` — the all-tags-with-usage fragment (and create form).
pub async fn list_tags(
    State(state): State<AppState>,
    Extension(_user): Extension<User>,
) -> Response {
    render_tag_list(&state).await
}

/// `POST /tags` — explicitly create a tag; returns the tag-list fragment.
pub async fn create_tag(
    State(state): State<AppState>,
    Extension(_user): Extension<User>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    let name = field(&form, "name").unwrap_or("");
    let color = nonempty(field(&form, "color"));
    let description = nonempty(field(&form, "description"));
    match state
        .annotations
        .create_tag(name, color.as_deref(), description.as_deref())
        .await
    {
        Ok(_) => render_tag_list(&state).await,
        Err(err) => annotate_err(err),
    }
}

/// `GET /scan/{id}/tags` — the session's applied-tags fragment (owner-checked).
pub async fn session_tags_fragment(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path(id): Path<Uuid>,
) -> Response {
    render_session_tags(&state, &user, id).await
}

/// `POST /scan/{id}/tags` — apply one or more tags (auto-creating new names);
/// returns the session's tags fragment.
pub async fn apply_tags(
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
    // A shared optional color is used only for names that must be created.
    let color = nonempty(field(&form, "color"));
    let tags: Vec<TagApply> = field(&form, "tags")
        .unwrap_or("")
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|name| TagApply {
            name: name.to_string(),
            color: color.clone(),
        })
        .collect();
    match state.annotations.apply_tags(&user, id, &tags).await {
        Ok(()) => render_session_tags(&state, &user, id).await,
        Err(err) => annotate_err(err),
    }
}

/// `POST /scan/{id}/tags/{tag_id}/remove` — remove a tag from a session.
pub async fn remove_tag(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Path((id, tag_id)): Path<(Uuid, i64)>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let form = parse_form(&body);
    if !auth::verify_csrf(&headers, field(&form, "_csrf")) {
        return forbidden();
    }
    match state.annotations.remove_tag(&user, id, tag_id).await {
        Ok(()) => render_session_tags(&state, &user, id).await,
        Err(err) => annotate_err(err),
    }
}

// --- Annotations: search / filter ------------------------------------------

/// `GET /search/notes?q=…` — sessions whose notes contain the term, scoped to
/// the viewer (admin spans all owners). Returns a session-list fragment.
pub async fn search_by_note(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Query(params): Query<NoteSearchParams>,
) -> Response {
    let term = params.q.as_deref().unwrap_or("").trim();
    if term.is_empty() {
        return auth::html(view::sessions_table(&[], &user), None);
    }
    match state.annotations.search_sessions_by_note(&user, term).await {
        Ok(sessions) => auth::html(view::sessions_table(&sessions, &user), None),
        Err(_) => server_error(),
    }
}

/// `GET /search/tags?tags=…&mode=all|any` — sessions carrying the named tags
/// (all or any), scoped to the viewer. Returns a session-list fragment.
pub async fn search_by_tags(
    State(state): State<AppState>,
    Extension(user): Extension<User>,
    Query(params): Query<TagSearchParams>,
) -> Response {
    let names: Vec<String> = params
        .tags
        .as_deref()
        .unwrap_or("")
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if names.is_empty() {
        return auth::html(view::sessions_table(&[], &user), None);
    }
    let match_all = params.mode.as_deref() == Some("all");
    match state
        .annotations
        .filter_sessions_by_tags(&user, &names, match_all)
        .await
    {
        Ok(sessions) => auth::html(view::sessions_table(&sessions, &user), None),
        Err(_) => server_error(),
    }
}

/// Query parameters for the note-text session search.
#[derive(Debug, Default, Deserialize)]
pub struct NoteSearchParams {
    q: Option<String>,
}

/// Query parameters for the tag session filter.
#[derive(Debug, Default, Deserialize)]
pub struct TagSearchParams {
    tags: Option<String>,
    mode: Option<String>,
}

// --- Annotation render helpers ---------------------------------------------

/// Re-render a note's scope (session-level or finding-level) after a mutation.
async fn render_note_scope(
    state: &AppState,
    user: &User,
    session_id: Uuid,
    finding_id: Option<FindingId>,
) -> Response {
    match finding_id {
        Some(fid) => render_finding_notes(state, user, session_id, fid).await,
        None => render_session_notes(state, user, session_id).await,
    }
}

/// Render the session notes fragment, mapping errors to a 404 or error fragment.
async fn render_session_notes(state: &AppState, user: &User, session_id: Uuid) -> Response {
    match state.annotations.session_notes(user, session_id).await {
        Ok(notes) => auth::html(view::notes_block(session_id, None, &notes), None),
        Err(err) => annotate_err(err),
    }
}

/// Render a finding's notes fragment.
async fn render_finding_notes(
    state: &AppState,
    user: &User,
    session_id: Uuid,
    finding_id: FindingId,
) -> Response {
    match state
        .annotations
        .finding_notes(user, session_id, finding_id)
        .await
    {
        Ok(notes) => auth::html(
            view::notes_block(session_id, Some(finding_id), &notes),
            None,
        ),
        Err(err) => annotate_err(err),
    }
}

/// Render a session's applied-tags fragment.
async fn render_session_tags(state: &AppState, user: &User, session_id: Uuid) -> Response {
    match state.annotations.session_tags(user, session_id).await {
        Ok(tags) => auth::html(view::session_tags_block(session_id, &tags), None),
        Err(err) => annotate_err(err),
    }
}

/// Render the all-tags list fragment.
async fn render_tag_list(state: &AppState) -> Response {
    match state.annotations.list_tags().await {
        Ok(tags) => auth::html(view::tag_list(&tags), None),
        Err(_) => server_error(),
    }
}

/// Map an annotation error to a response: an ownership/visibility denial (or
/// unknown session) yields a `404`, disclosing nothing; a validation error
/// renders inline as an error fragment.
fn annotate_err(err: abyssum_core::Error) -> Response {
    match err {
        abyssum_core::Error::Auth(_) => not_visible(),
        other => auth::html(view::error_fragment(&clean_err(other)), None),
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
            "{}<p><a href=\"/scan\">Back to start</a></p>",
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

/// Collect the scan form's per-scan options: every field named `opt.<key>` becomes
/// option `<key>`. The scan form namespaces its option inputs under this prefix, so
/// a feature that adds one (a brute-force toggle, a timing profile, a wordlist
/// choice) flows through here with no change to this handler. A form with no such
/// field yields an empty [`ScanOptions`] and the scan applies defaults.
fn scan_options_from_form(form: &[(String, String)]) -> ScanOptions {
    let mut options = ScanOptions::new();
    for (key, value) in form {
        if let Some(name) = key.strip_prefix("opt.") {
            options.set(name, value.clone());
        }
    }
    options
}

/// Decode one `application/x-www-form-urlencoded` component (`+` → space, `%XX`).
fn percent_decode(input: &str) -> String {
    let spaced = input.replace('+', " ");
    let bytes = spaced.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
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
    fn scan_options_from_form_collects_only_opt_prefixed_fields() {
        // No `opt.` field → empty options (the scan applies defaults).
        let bare = parse_form("scanners=cors&targets=https%3A%2F%2Fa.test");
        assert!(scan_options_from_form(&bare).is_empty());

        // `opt.<key>` fields are carried, stripped of the prefix; other fields are
        // ignored. This is the seam the feature changes hook their inputs into.
        let form = parse_form("scanners=cors&opt.timing_profile=organic&opt.brute=on");
        let options = scan_options_from_form(&form);
        assert_eq!(options.get("timing_profile"), Some("organic"));
        assert_eq!(options.get("brute"), Some("on"));
        assert_eq!(options.get("scanners"), None);
    }

    #[test]
    fn policy_from_form_rejects_out_of_range_delays() {
        let form = |s: &str| parse_form(s);
        // A sane window parses into the matching shape.
        assert!(matches!(
            policy_from_form(&form("shape=uniform&min=1&max=3")).unwrap(),
            PacingPolicy::Uniform { .. }
        ));
        assert!(matches!(
            policy_from_form(&form("shape=organic&min=1&max=6")).unwrap(),
            PacingPolicy::Organic { .. }
        ));
        // A finite-but-huge value that would overflow Duration is rejected, not stored.
        assert!(policy_from_form(&form("shape=uniform&min=0&max=1e300")).is_err());
        // Negatives and non-numbers are rejected too.
        assert!(policy_from_form(&form("shape=uniform&min=-1&max=3")).is_err());
        assert!(policy_from_form(&form("shape=uniform&min=x&max=3")).is_err());
        // The ceiling itself is allowed (boundary), one past it is not.
        assert!(policy_from_form(&form("shape=uniform&min=0&max=86400")).is_ok());
        assert!(policy_from_form(&form("shape=uniform&min=0&max=86401")).is_err());
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
