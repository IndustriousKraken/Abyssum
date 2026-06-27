//! Shared application state, the router, and the server bind/serve path.
//!
//! [`AppState`] is the surface-agnostic engine wired up once at startup — config,
//! the persistence layer, the authentication service, the scan orchestrator, the
//! live-progress hub, and a session-scoped rate limiter for the custom-requests
//! tool — and handed to every handler. The router mounts the public routes, the
//! authenticated page/data routes (each behind the matching auth gate), and the
//! static assets.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use abyssum_core::{
    AnnotationStore, AuthManager, Config, DatabaseManager, Orchestrator, RateLimiter,
    ScannerRegistry,
};
use abyssum_scanners::register_builtins;
use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::{from_fn, from_fn_with_state, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;
use tower_http::services::ServeDir;

use crate::auth::{require_user_data, require_user_page, LoginLimiter};
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
        let limiter = RateLimiter::from_config(&config.scanning);
        let orchestrator = Arc::new(Orchestrator::new(config.clone(), registry));

        Ok(Self {
            config,
            db,
            auth,
            annotations,
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
pub fn build_router(state: AppState, static_dir: impl AsRef<Path>) -> Router {
    // Pages: a missing session redirects the browser to the login page.
    let page_routes = Router::new()
        .route("/", get(handlers::home))
        .route("/dashboard", get(handlers::dashboard))
        .route("/scan/{id}", get(handlers::scan_detail))
        .route("/custom-requests", get(handlers::custom_page))
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

    Router::new()
        .merge(public_routes)
        .merge(page_routes)
        .merge(data_routes)
        .nest_service("/static", ServeDir::new(static_dir.as_ref()))
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
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
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

/// Resolve the static-asset directory: `ABYSSUM_WEB_STATIC` if set, else the
/// `static/` directory beside this crate (dev/test). A shipped binary points this
/// at the installed asset path via the env var; a missing dir simply 404s.
pub fn default_static_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ABYSSUM_WEB_STATIC") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static")
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
