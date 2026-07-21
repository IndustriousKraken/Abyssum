//! Static assets compiled into the binary.
//!
//! A shipped `abyssum-web` carries no companion files, so the `/static/*` assets
//! are embedded here with `include_bytes!` and served by [`serve`]. This is the
//! default; setting `ABYSSUM_WEB_STATIC` overrides it with a filesystem
//! directory (dev live-reload, custom themes) — see [`crate::state::build_router`].
//!
//! ponytail: a four-entry `match` beats pulling in `rust-embed`/`axum-embed` for
//! four files. Add a crate only if this list grows into a real asset tree.

use axum::extract::Path;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

/// Serve one embedded asset by its `/static/{path}` tail, or 404. The four assets
/// are the ones `view.rs` references; the `Content-Type` matches each extension.
pub async fn serve(Path(path): Path<String>) -> Response {
    let (content_type, bytes): (&str, &[u8]) = match path.as_str() {
        "app.css" => (
            "text/css; charset=utf-8",
            include_bytes!("../static/app.css"),
        ),
        "app.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../static/app.js"),
        ),
        "htmx.min.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../static/htmx.min.js"),
        ),
        "alpine.min.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("../static/alpine.min.js"),
        ),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    // ponytail: cache for a day — these bytes only change across releases. Not
    // `immutable`: the URLs aren't content-hashed, so a browser must revalidate
    // eventually or a binary update can't invalidate stale app.css/app.js.
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        bytes,
    )
        .into_response()
}
