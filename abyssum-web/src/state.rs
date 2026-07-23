//! Shared application state, the router, and the server bind/serve path.
//!
//! [`AppState`] is the surface-agnostic engine wired up once at startup — config,
//! the persistence layer, the authentication service, the scan orchestrator, the
//! live-progress hub, and a session-scoped rate limiter for the custom-requests
//! tool — and handed to every handler. The router mounts the public routes, the
//! authenticated page/data routes (each behind the matching auth gate), and the
//! static assets.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use abyssum_core::{
    AnnotationStore, AuthManager, Config, CustomWordlistStore, DatabaseManager, EngagementStore,
    Orchestrator, RateLimiter, ScannerRegistry, TimingProfileStore,
};
use abyssum_scanners::register_builtins;
use axum::Router;
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::HeaderValue;
use axum::middleware::{Next, from_fn, from_fn_with_state};
use axum::response::Response;
use axum::routing::{get, post};
use tower_http::services::ServeDir;

use crate::assets;
use crate::auth::{LoginLimiter, require_user_data, require_user_page};
use crate::handlers;
use crate::ws::Hub;

/// The shared engine state every handler is given. Cheap to clone — every field
/// is itself an `Arc`/pool handle.
#[derive(Clone)]
pub struct AppState {
    /// Resolved runtime configuration.
    pub config: Arc<Config>,
    /// The result store (sessions + findings), shared with auth.
    pub db: DatabaseManager,
    /// The authentication authority (login, sessions, ownership).
    pub auth: AuthManager,
    /// Notes + color tags over sessions and findings, gated by session ownership.
    pub annotations: AnnotationStore,
    /// Per-user timing profiles (reusable pacing shapes), gated by owner.
    pub timing: TimingProfileStore,
    /// Per-user custom wordlists (imported reference lists), gated by owner.
    pub wordlists: CustomWordlistStore,
    /// Engagements: scan groupings + scope/authorization documents, gated by the
    /// engagement's authorized-operator set (admin sees all).
    pub engagements: EngagementStore,
    /// The scan engine, shared so background runs and handlers drive one engine.
    pub orchestrator: Arc<Orchestrator>,
    /// Live per-session progress fan-out for the WebSocket endpoint.
    pub hub: Hub,
    /// One session-scoped rate limiter for the custom-requests tool, so repeated
    /// requests to a host are paced (a fresh limiter per call would defeat that).
    pub limiter: RateLimiter,
    /// Per-source-IP throttle for the login/register POSTs (brute-force defense).
    pub login_limiter: LoginLimiter,
}

impl AppState {
    /// Build the full engine from a resolved [`Config`]: open and seed the store,
    /// register the built-in scanners, and wire auth + orchestration over it.
    pub async fn build(config: Config) -> abyssum_core::Result<Self> {
        let db = DatabaseManager::connect_from_config(&config).await?;
        let config = Arc::new(config);

        let mut registry = ScannerRegistry::new(config.clone());
        register_builtins(&mut registry, &db.reference_store());

        let auth = AuthManager::from_database(&db, &config);
        let annotations = AnnotationStore::from_database(&db);
        let timing = TimingProfileStore::from_database(&db);
        let wordlists = CustomWordlistStore::from_database(&db);
        let engagements = EngagementStore::from_database(&db);
        let limiter = RateLimiter::from_config(&config.scanning);
        let orchestrator = Arc::new(Orchestrator::new(config.clone(), registry));

        Ok(Self {
            config,
            db,
            auth,
            annotations,
            timing,
            wordlists,
            engagements,
            orchestrator,
            hub: Hub::default(),
            limiter,
            login_limiter: LoginLimiter::default(),
        })
    }
}

/// Build the router: public routes, authenticated page routes (redirect on no
/// session), authenticated data/WebSocket routes (reject on no session), and the
/// static asset service. Axum 0.8 path-param syntax is `{name}`.
///
/// `static_dir` selects how `/static/*` is served: `Some(dir)` serves from that
/// filesystem directory (the `ABYSSUM_WEB_STATIC` override — dev live-reload,
/// custom themes); `None` serves the assets embedded in the binary (see
/// [`assets`]), which is the default a shipped binary uses.
pub fn build_router(state: AppState, static_dir: Option<PathBuf>) -> Router {
    // Pages: a missing session redirects the browser to the login page.
    let page_routes = Router::new()
        // The dashboard is the default post-login landing at `/`; the start-scan
        // page keeps its own route (`/scan`), reachable from the nav.
        .route("/", get(handlers::dashboard))
        .route("/scan", get(handlers::scan_page))
        .route("/dashboard", get(handlers::dashboard))
        .route("/scan/{id}", get(handlers::scan_detail))
        .route("/custom-requests", get(handlers::custom_page))
        .route("/timing-profiles", get(handlers::timing_profiles_page))
        .route("/wordlists", get(handlers::wordlists_page))
        .route("/engagements", get(handlers::engagements_page))
        .route("/engagements/{id}", get(handlers::engagement_detail))
        .route("/logout", post(handlers::logout))
        .route_layer(from_fn_with_state(state.clone(), require_user_page));

    // Data & WebSocket: a missing session is rejected as unauthorized.
    let data_routes = Router::new()
        .route("/scans", post(handlers::start_scan))
        .route("/scan/{id}/results", get(handlers::scan_results))
        .route("/scan/{id}/cancel", post(handlers::cancel_scan))
        .route("/sessions", get(handlers::sessions_fragment))
        .route("/stats", get(handlers::stats_fragment))
        .route("/findings", get(handlers::findings_fragment))
        .route("/custom-requests", post(handlers::custom_exec))
        // Timing-profile management: create a profile, adjust an existing one.
        .route("/timing-profiles", post(handlers::create_timing_profile))
        .route(
            "/timing-profiles/{id}",
            post(handlers::update_timing_profile),
        )
        // Custom-wordlist import (paste or .txt upload), owned by the user.
        .route("/wordlists", post(handlers::import_wordlist))
        // Engagements: create, attach a document, serve a document safely, and
        // assign a scan to an engagement. All gated by the engagement's authorized
        // operators (admin sees all) in the handlers.
        .route("/engagements", post(handlers::create_engagement))
        // Raise this route's request-body limit above axum's 2 MiB default, sized
        // from `max_document_bytes`, so a legal document upload reaches the handler
        // (and the store's clear size error) instead of a bare 413 from axum.
        .route(
            "/engagements/{id}/documents",
            post(handlers::attach_document).layer(DefaultBodyLimit::max(
                handlers::document_body_cap(state.config.server.max_document_bytes),
            )),
        )
        .route(
            "/engagements/{id}/documents/{doc_id}",
            get(handlers::serve_document),
        )
        .route("/scan/{id}/assign", post(handlers::assign_scan))
        // Annotations: notes on sessions/findings, color tags, and the
        // note/tag-scoped session searches. All owner-gated in the handlers.
        .route(
            "/scan/{id}/notes",
            get(handlers::session_notes_fragment).post(handlers::add_session_note),
        )
        .route(
            "/scan/{id}/findings/{fid}/notes",
            get(handlers::finding_notes_fragment).post(handlers::add_finding_note),
        )
        // Best-effort AI analysis of one finding (owner-gated in the handler).
        .route(
            "/scan/{id}/findings/{fid}/analyze",
            post(handlers::analyze_finding),
        )
        .route("/notes/{note_id}/edit", post(handlers::edit_note))
        .route("/notes/{note_id}/delete", post(handlers::delete_note))
        .route("/tags", get(handlers::list_tags).post(handlers::create_tag))
        .route(
            "/scan/{id}/tags",
            get(handlers::session_tags_fragment).post(handlers::apply_tags),
        )
        .route(
            "/scan/{id}/tags/{tag_id}/remove",
            post(handlers::remove_tag),
        )
        .route("/search/notes", get(handlers::search_by_note))
        .route("/search/tags", get(handlers::search_by_tags))
        .route("/ws/{id}", get(handlers::ws_handler))
        .route_layer(from_fn_with_state(state.clone(), require_user_data));

    // Public: login + registration (no session required).
    let public_routes = Router::new()
        .route(
            "/login",
            get(handlers::login_page).post(handlers::login_submit),
        )
        .route(
            "/register",
            get(handlers::register_page).post(handlers::register_submit),
        );

    let router = Router::new()
        .merge(public_routes)
        .merge(page_routes)
        .merge(data_routes);
    // Serve `/static/*` from the override directory when set, else the embedded
    // copy compiled into the binary.
    let router = match static_dir {
        Some(dir) => router.nest_service("/static", ServeDir::new(dir)),
        None => router.route("/static/{*path}", get(assets::serve)),
    };
    router
        .with_state(state)
        // Stamp security headers on every response (pages, fragments, static
        // assets, errors) — wraps the whole router so nothing escapes uncovered.
        .layer(from_fn(security_headers))
}

/// The Content-Security-Policy. Scripts and styles are same-origin only, except
/// for the two exceptions the Alpine-driven UI genuinely needs: `'unsafe-eval'`
/// for Alpine's expression evaluator (it compiles `x-bind`/`x-data` expressions
/// with `Function()`), and `'unsafe-inline'` styles for the inline `style=`
/// attributes the server-rendered markup uses. Everything else (connect for the
/// live-progress WebSocket, images, fonts) falls back to `default-src 'self'`,
/// and framing is denied outright.
///
/// ponytail: dropping `'unsafe-eval'` would require shipping Alpine's separate
/// CSP build and a nonce/hashing pass — a packaging change. Tighten here if the
/// UI ever moves to that build.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
     script-src 'self' 'unsafe-eval'; \
     style-src 'self' 'unsafe-inline'; \
     frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

/// Attach the defense-in-depth security response headers to every response:
/// CSP (above), clickjacking protection, MIME-sniffing off, and HSTS. HSTS is
/// only honored by browsers over TLS (ignored on plain HTTP per RFC 6797), so
/// sending it unconditionally is safe and upgrades a first HTTPS visit.
async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    // CSP and framing default to the strict page policy, but a handler MAY set its
    // own first (the engagement document endpoint serves untrusted bytes with a
    // `sandbox` CSP and allows same-origin framing so an uploaded PDF renders
    // inline). Only fill these in when the handler left them unset, so that
    // per-response override is not clobbered here.
    if !headers.contains_key("content-security-policy") {
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static(CONTENT_SECURITY_POLICY),
        );
    }
    if !headers.contains_key("x-frame-options") {
        headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    }
    // MIME-sniffing is off on every response, without exception.
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        "strict-transport-security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    resp
}

/// The static-asset override: `Some(dir)` when `ABYSSUM_WEB_STATIC` is set, else
/// `None` to serve the assets embedded in the binary. No build-time path (e.g.
/// `CARGO_MANIFEST_DIR`) is baked in — a shipped binary is self-contained, and
/// the override is only for dev live-reload or custom themes.
pub fn default_static_dir() -> Option<PathBuf> {
    // Reject an empty value: `ABYSSUM_WEB_STATIC=` would otherwise become
    // `ServeDir::new("")`, silently serving the process CWD.
    std::env::var_os("ABYSSUM_WEB_STATIC")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// Build the engine and serve until the process is stopped. Binds the configured
/// host/port and logs the bound address.
pub async fn serve(config: Config) -> abyssum_core::Result<()> {
    let host = config.server.host.clone();
    let port = config.server.port;
    let state = AppState::build(config).await?;
    let app = build_router(state, default_static_dir());

    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| abyssum_core::Error::Other(format!("failed to bind {addr}: {e}")))?;
    let bound = listener
        .local_addr()
        .map_err(|e| abyssum_core::Error::Other(format!("failed to read bound address: {e}")))?;
    tracing::info!(%bound, "abyssum-web listening");
    println!("abyssum-web listening on http://{bound}");

    // `into_make_service_with_connect_info` so handlers can read the peer address
    // (the auth POSTs throttle per source IP).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| abyssum_core::Error::Other(format!("server error: {e}")))
}
