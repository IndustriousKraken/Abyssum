//! A small read-only HTTP API over the traffic store, plus the replay endpoint.
//!
//! The capture store is only useful to *other* tools and agents if they can reach
//! it, so this exposes it over the wire (JSON) — the seam the proposal calls for.
//! It is deliberately minimal and read-only, save for `POST /replay`, which re-issues
//! a stored request through the paced send path (see [`crate::replay`]).
//!
//! Routes (all JSON unless noted):
//! - `GET  /exchanges?<filters>` — matching captured exchanges (the read query).
//! - `GET  /export/{har|openapi|raw|postman}?<filters>` — the filtered set, exported.
//! - `POST /replay` — `{ "id": N, "method"?, "url"?, "headers"?: {..}, "body"?: str }`;
//!   replays exchange `N` with the modifications and returns the captured result.
//!
//! `<filters>` are the same dimensions the store indexes: `endpoint`, `host`,
//! `status`, `param`, `header`, `flag`, `from`/`to` (RFC 3339), `limit`, and
//! `interest_first`.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::error::Result;
use crate::export::ExportFormat;
use crate::replay::{ReplayModifications, Replayer};
use crate::store::{StoredExchange, TrafficQuery, TrafficStore};

/// The API's response body type (boxed; bodies are fully buffered).
type ApiBody = BoxBody<Bytes, Infallible>;

/// What the API server needs: the store to read/export, and the replayer to re-issue
/// captured requests through the paced path.
#[derive(Clone)]
pub struct ApiState {
    /// The traffic store to query and export.
    pub store: TrafficStore,
    /// The paced replayer.
    pub replayer: Replayer,
}

/// Accept connections on `listener` forever, serving the read/replay API on each.
/// Returns only on an accept error.
pub async fn serve(listener: TcpListener, state: Arc<ApiState>) -> Result<()> {
    loop {
        let (stream, _peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(handle(state, req).await) }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                tracing::debug!(error = %e, "proxy API connection ended with error");
            }
        });
    }
}

/// Route one API request. Never returns `Err` — failures become status responses.
pub async fn handle(state: Arc<ApiState>, req: Request<Incoming>) -> Response<ApiBody> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let raw_query = req.uri().query().map(str::to_string);

    match (&method, path.as_str()) {
        (&Method::GET, "/exchanges") => match query_store(&state.store, raw_query.as_deref()).await
        {
            Ok(rows) => {
                let body = Value::Array(rows.iter().map(exchange_to_json).collect());
                json_response(StatusCode::OK, &body)
            }
            Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        },
        (&Method::GET, p) if p.starts_with("/export/") => {
            let Some(format) = ExportFormat::from_name(&p["/export/".len()..]) else {
                return error_response(StatusCode::NOT_FOUND, "unknown export format");
            };
            match query_store(&state.store, raw_query.as_deref()).await {
                Ok(rows) => {
                    body_response(StatusCode::OK, format.content_type(), format.export(&rows))
                }
                Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
            }
        }
        (&Method::POST, "/replay") => replay(state, req).await,
        _ => error_response(StatusCode::NOT_FOUND, "not found"),
    }
}

/// Run the store query described by the request's query string.
async fn query_store(store: &TrafficStore, raw_query: Option<&str>) -> Result<Vec<StoredExchange>> {
    store.query(&build_query(raw_query)).await
}

/// Build a [`TrafficQuery`] from the request's `?...` filters.
fn build_query(raw_query: Option<&str>) -> TrafficQuery {
    let mut q = TrafficQuery::new();
    for (key, value) in form_pairs(raw_query) {
        match key.as_str() {
            "endpoint" => q.endpoint = Some(value),
            "host" => q.host = Some(value),
            "param" => q.param = Some(value),
            "header" => q.header = Some(value),
            "flag" => q.flag = Some(value),
            "status" => q.status = value.parse().ok(),
            "limit" => q.limit = value.parse().ok(),
            "from" => q.from = parse_time(&value),
            "to" => q.to = parse_time(&value),
            "interest_first" => q.interest_first = is_truthy(&value),
            _ => {}
        }
    }
    q
}

/// Handle `POST /replay`: parse the modifications, replay through the paced path,
/// and return the captured result.
async fn replay(state: Arc<ApiState>, req: Request<Incoming>) -> Response<ApiBody> {
    let bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("reading body: {e}")),
    };
    let spec: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")),
    };
    let Some(id) = spec.get("id").and_then(Value::as_i64) else {
        return error_response(StatusCode::BAD_REQUEST, "replay requires an integer \"id\"");
    };

    let mods = ReplayModifications {
        method: spec
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_string),
        url: spec.get("url").and_then(Value::as_str).map(str::to_string),
        headers: spec.get("headers").and_then(Value::as_object).map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                .collect()
        }),
        body: spec
            .get("body")
            .and_then(Value::as_str)
            .map(|s| s.as_bytes().to_vec()),
    };

    match state.replayer.replay_stored(id, &mods).await {
        Ok(row) => json_response(StatusCode::OK, &exchange_to_json(&row)),
        Err(e) => error_response(StatusCode::BAD_GATEWAY, &e.to_string()),
    }
}

/// The JSON view of a stored exchange the read API returns.
// ponytail: bodies are UTF-8 (lossy) strings — right for the JSON/text API traffic
// this observes; add a base64 field if binary-body fidelity over the API ever matters.
pub fn exchange_to_json(row: &StoredExchange) -> Value {
    let ex = &row.exchange;
    json!({
        "id": row.id,
        "method": ex.method,
        "url": ex.url,
        "host": ex.host,
        "endpoint": ex.endpoint,
        "query": ex.query,
        "params": ex.params,
        "request_headers": header_list(&ex.req_headers),
        "request_body": String::from_utf8_lossy(&ex.req_body),
        "request_body_truncated": ex.req_body_truncated,
        "status": ex.status,
        "response_headers": header_list(&ex.resp_headers),
        "response_body": String::from_utf8_lossy(&ex.resp_body),
        "response_body_truncated": ex.resp_body_truncated,
        "started_at": ex.started_at.to_rfc3339(),
        "duration_ms": ex.duration_ms,
        "flags": row.flags.iter().map(|f| f.label()).collect::<Vec<_>>(),
        "score": row.score,
    })
}

/// Header name/value pairs as a JSON list (preserves order and duplicates).
fn header_list(headers: &[(String, String)]) -> Value {
    Value::Array(
        headers
            .iter()
            .map(|(k, v)| json!({ "name": k, "value": v }))
            .collect(),
    )
}

/// Parse an RFC 3339 timestamp into UTC (returns `None` on a malformed value).
fn parse_time(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Whether a query-flag value counts as "on".
fn is_truthy(s: &str) -> bool {
    matches!(
        s.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on" | ""
    )
}

/// Decode a `key=value&...` query string (percent-decoding both sides).
fn form_pairs(raw_query: Option<&str>) -> Vec<(String, String)> {
    match raw_query {
        Some(q) => url::form_urlencoded::parse(q.as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect(),
        None => Vec::new(),
    }
}

/// A JSON response with the given status.
fn json_response(status: StatusCode, value: &Value) -> Response<ApiBody> {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    body_response_bytes(status, "application/json", Bytes::from(body))
}

/// A `{"error": msg}` JSON response with the given status.
fn error_response(status: StatusCode, message: &str) -> Response<ApiBody> {
    json_response(status, &json!({ "error": message }))
}

/// A response carrying a string body with an explicit content type.
fn body_response(status: StatusCode, content_type: &str, body: String) -> Response<ApiBody> {
    body_response_bytes(status, content_type, Bytes::from(body))
}

/// A response carrying raw bytes with an explicit content type.
fn body_response_bytes(status: StatusCode, content_type: &str, body: Bytes) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .body(Full::new(body).boxed())
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new()).boxed()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_reads_every_filter() {
        let q = build_query(Some(
            "endpoint=/api/users&host=api.test&status=404&param=id&header=authorization\
             &flag=idor&limit=5&interest_first=true&from=2020-01-01T00:00:00Z",
        ));
        assert_eq!(q.endpoint.as_deref(), Some("/api/users"));
        assert_eq!(q.host.as_deref(), Some("api.test"));
        assert_eq!(q.status, Some(404));
        assert_eq!(q.param.as_deref(), Some("id"));
        assert_eq!(q.header.as_deref(), Some("authorization"));
        assert_eq!(q.flag.as_deref(), Some("idor"));
        assert_eq!(q.limit, Some(5));
        assert!(q.interest_first);
        assert!(q.from.is_some());
        assert!(q.to.is_none());
    }

    #[test]
    fn percent_encoded_filters_decode() {
        // `/api/a b` with the space percent-encoded.
        let q = build_query(Some("endpoint=%2Fapi%2Fa%20b"));
        assert_eq!(q.endpoint.as_deref(), Some("/api/a b"));
    }

    #[test]
    fn truthiness() {
        assert!(is_truthy("true"));
        assert!(is_truthy("1"));
        assert!(is_truthy("")); // bare `?interest_first` present
        assert!(!is_truthy("false"));
        assert!(!is_truthy("0"));
    }
}
