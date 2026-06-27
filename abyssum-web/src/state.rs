//! Shared application state, the router, and the server bind/serve path.
//!
//! [`AppState`] is the surface-agnostic engine wired up once at startup — config,
//! the persistence layer, the authentication service, the scan orchestrator, the
//! live-progress hub, and a session-scoped rate limiter for the custom-requests
//! tool — and handed to every handler. The router mounts the public routes, the
//! authenticated page/data routes (each behind the matching auth gate), and the
//! static assets.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use abyssum_core::{
    AuthManager, Config, DatabaseManager, Orchestrator, RateLimiter, ScannerRegistry,
};
use abyssum_scanners::register_builtins;
use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use axum::Router;
use tower_http::services::ServeDir;

use crate::auth::{require_user_data, require_user_page};
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
    /// The scan engine, shared so background runs and handlers drive one engine.
    pub orchestrator: Arc<Orchestrator>,
    /// Live per-session progress fan-out for the WebSocket endpoint.
    pub hub: Hub,
    /// One session-scoped rate limiter for the custom-requests tool, so repeated
    /// requests to a host are paced (a fresh limiter per call would defeat that).
    pub limiter: RateLimiter,
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
        let limiter = RateLimiter::from_config(&config.scanning);
        let orchestrator = Arc::new(Orchestrator::new(config.clone(), registry));

        Ok(Self {
            config,
            db,
            auth,
            orchestrator,
            hub: Hub::default(),
            limiter,
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

    axum::serve(listener, app.into_make_service())
        .await
        .map_err(|e| abyssum_core::Error::Other(format!("server error: {e}")))
}
