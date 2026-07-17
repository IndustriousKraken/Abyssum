//! Export captured traffic into interchange formats — pure functions over stored
//! exchanges → bytes (see `design.md`).
//!
//! - **HAR** ([`to_har`]) is a direct serialization of the captured exchanges into
//!   an HTTP Archive 1.2 document (Burp, browser devtools, and most proxies read it).
//! - **OpenAPI** ([`to_openapi`]) is *synthesized*: exchanges are grouped by method
//!   and a best-effort path template (numeric / UUID segments collapse to `{id}`),
//!   and parameters and response shapes are inferred from the observed examples. It
//!   is explicitly marked best-effort — an account of what was *seen*, not a
//!   guarantee of completeness.
//! - **Raw** ([`to_raw`]) is the verbatim request/response text of each exchange.
//! - **Postman** ([`to_postman`]) is a v2.1 collection on the same read path — a
//!   nice-to-have for driving captured requests from Postman.
//!
//! Every function takes the exchanges a caller already pulled from the store (via
//! [`TrafficStore::query`](crate::store::TrafficStore::query)), so the same filtered
//! set the read API returns is exactly what gets exported.

use serde_json::{Value, json};

use crate::store::StoredExchange;

/// This crate's version, stamped into HAR/OpenAPI/Postman metadata.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The interchange formats captured traffic can be exported to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// HTTP Archive 1.2 (`application/json`).
    Har,
    /// Synthesized OpenAPI 3.0 description (`application/json`).
    OpenApi,
    /// Verbatim request/response text (`text/plain`).
    Raw,
    /// Postman collection v2.1 (`application/json`).
    Postman,
}

impl ExportFormat {
    /// Parse a format name (as used in the read API path / CLI), case-insensitively.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "har" => Some(Self::Har),
            "openapi" | "oas" => Some(Self::OpenApi),
            "raw" => Some(Self::Raw),
            "postman" => Some(Self::Postman),
            _ => None,
        }
    }

    /// The `Content-Type` an exported document of this format should be served with.
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Har | Self::OpenApi | Self::Postman => "application/json",
            Self::Raw => "text/plain; charset=utf-8",
        }
    }

    /// Export `exchanges` in this format.
    pub fn export(self, exchanges: &[StoredExchange]) -> String {
        match self {
            Self::Har => to_har(exchanges),
            Self::OpenApi => to_openapi(exchanges),
            Self::Raw => to_raw(exchanges),
            Self::Postman => to_postman(exchanges),
        }
    }
}

/// Serialize captured exchanges to an HTTP Archive (HAR) 1.2 document.
pub fn to_har(exchanges: &[StoredExchange]) -> String {
    let entries: Vec<Value> = exchanges.iter().map(har_entry).collect();
    let doc = json!({
        "log": {
            "version": "1.2",
            "creator": { "name": "abyssum-proxy", "version": VERSION },
            "entries": entries,
        }
    });
    to_pretty(&doc)
}

/// One HAR `entries[]` object for a stored exchange.
fn har_entry(row: &StoredExchange) -> Value {
    let ex = &row.exchange;
    let req_body = String::from_utf8_lossy(&ex.req_body);
    let resp_body = String::from_utf8_lossy(&ex.resp_body);

    let mut request = json!({
        "method": ex.method,
        "url": ex.url,
        "httpVersion": "HTTP/1.1",
        "headers": har_headers(&ex.req_headers),
        "queryString": har_query(ex.query.as_deref()),
        "cookies": [],
        "headersSize": -1,
        "bodySize": ex.req_body.len(),
    });
    if !ex.req_body.is_empty() {
        request["postData"] = json!({
            "mimeType": content_type(&ex.req_headers).unwrap_or("application/octet-stream"),
            "text": req_body,
        });
    }

    json!({
        "startedDateTime": ex.started_at.to_rfc3339(),
        "time": ex.duration_ms,
        "request": request,
        "response": {
            "status": ex.status,
            "statusText": "",
            "httpVersion": "HTTP/1.1",
            "headers": har_headers(&ex.resp_headers),
            "cookies": [],
            "content": {
                "size": ex.resp_body.len(),
                "mimeType": content_type(&ex.resp_headers).unwrap_or("application/octet-stream"),
                "text": resp_body,
            },
            "redirectURL": location(&ex.resp_headers).unwrap_or_default(),
            "headersSize": -1,
            "bodySize": ex.resp_body.len(),
        },
        "cache": {},
        "timings": { "send": 0, "wait": ex.duration_ms, "receive": 0 },
    })
}

/// HAR name/value header list.
fn har_headers(headers: &[(String, String)]) -> Value {
    Value::Array(
        headers
            .iter()
            .map(|(k, v)| json!({ "name": k, "value": v }))
            .collect(),
    )
}

/// HAR `queryString` name/value list parsed from the raw query.
fn har_query(query: Option<&str>) -> Value {
    let mut out = Vec::new();
    for (name, value) in query_pairs(query) {
        out.push(json!({ "name": name, "value": value }));
    }
    Value::Array(out)
}

/// Synthesize a best-effort OpenAPI 3.0 description from the observed exchanges.
///
/// Exchanges are grouped by (path template, method); numeric / UUID path segments
/// collapse to `{id}` templates so `/users/1` and `/users/2` become one
/// `/users/{id}` path. Query parameters and response bodies are inferred from the
/// observed examples. The `info.description` states plainly that this is
/// best-effort — an account of observed traffic, not a complete contract.
pub fn to_openapi(exchanges: &[StoredExchange]) -> String {
    use std::collections::BTreeMap;

    // path template -> method (lowercase) -> aggregated observations.
    let mut paths: BTreeMap<String, BTreeMap<String, MethodAgg>> = BTreeMap::new();
    // path template -> ordered path-parameter names (shared across its methods).
    let mut path_params: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for row in exchanges {
        let ex = &row.exchange;
        let (template, params) = path_template(&ex.endpoint);
        path_params.entry(template.clone()).or_insert(params);

        let agg = paths
            .entry(template)
            .or_default()
            .entry(ex.method.to_ascii_lowercase())
            .or_default();

        for name in &ex.params {
            if !agg.query_params.contains(name) {
                agg.query_params.push(name.clone());
            }
        }
        if !ex.req_body.is_empty() && agg.request_example.is_none() {
            agg.request_example = Some(body_example(&ex.req_headers, &ex.req_body));
        }
        agg.responses
            .entry(ex.status)
            .or_insert_with(|| body_example(&ex.resp_headers, &ex.resp_body));
    }

    let mut paths_obj = serde_json::Map::new();
    for (template, methods) in &paths {
        let params = path_params.get(template).cloned().unwrap_or_default();
        let mut ops = serde_json::Map::new();
        for (method, agg) in methods {
            ops.insert(method.clone(), openapi_operation(method, &params, agg));
        }
        paths_obj.insert(template.clone(), Value::Object(ops));
    }

    let doc = json!({
        "openapi": "3.0.3",
        "info": {
            "title": "Observed API (best-effort)",
            "version": "0.0.0",
            "description": "Synthesized from traffic observed by the Abyssum proxy. \
                BEST-EFFORT: this describes only what was seen on the wire and is not \
                a guarantee of completeness or correctness.",
        },
        "paths": Value::Object(paths_obj),
    });
    to_pretty(&doc)
}

/// Observations aggregated for one (path template, method).
#[derive(Default)]
struct MethodAgg {
    /// Query-parameter names seen on this operation, in first-seen order.
    query_params: Vec<String>,
    /// One observed request body example, if any request carried a body.
    request_example: Option<(String, Value)>,
    /// One observed response example per status code.
    responses: std::collections::BTreeMap<u16, (String, Value)>,
}

/// Build one OpenAPI operation object from the aggregated observations.
fn openapi_operation(method: &str, path_params: &[String], agg: &MethodAgg) -> Value {
    let mut parameters = Vec::new();
    for name in path_params {
        parameters.push(json!({
            "name": name,
            "in": "path",
            "required": true,
            "schema": { "type": "string" },
        }));
    }
    for name in &agg.query_params {
        parameters.push(json!({
            "name": name,
            "in": "query",
            "required": false,
            "schema": { "type": "string" },
        }));
    }

    let mut responses = serde_json::Map::new();
    for (status, (ct, example)) in &agg.responses {
        responses.insert(
            status.to_string(),
            json!({
                "description": "Observed response",
                "content": { ct: { "example": example } },
            }),
        );
    }
    if responses.is_empty() {
        responses.insert(
            "default".into(),
            json!({ "description": "Observed response" }),
        );
    }

    let mut op = json!({
        "summary": format!("Observed {} traffic", method.to_ascii_uppercase()),
        "parameters": parameters,
        "responses": Value::Object(responses),
    });
    if let Some((ct, example)) = &agg.request_example {
        op["requestBody"] = json!({
            "content": { ct: { "example": example } },
        });
    }
    op
}

/// Emit the verbatim request/response text of each exchange, one block per exchange.
pub fn to_raw(exchanges: &[StoredExchange]) -> String {
    let mut out = String::new();
    for row in exchanges {
        let ex = &row.exchange;
        out.push_str(&format!("===== Exchange {} =====\n", row.id));

        // Request.
        let target = request_target(&ex.url);
        out.push_str(&format!("{} {} HTTP/1.1\n", ex.method, target));
        for (name, value) in &ex.req_headers {
            out.push_str(&format!("{name}: {value}\n"));
        }
        out.push('\n');
        if !ex.req_body.is_empty() {
            out.push_str(&String::from_utf8_lossy(&ex.req_body));
            if ex.req_body_truncated {
                out.push_str("\n[...truncated...]");
            }
            out.push('\n');
        }

        // Response.
        out.push_str(&format!("\nHTTP/1.1 {}\n", ex.status));
        for (name, value) in &ex.resp_headers {
            out.push_str(&format!("{name}: {value}\n"));
        }
        out.push('\n');
        if !ex.resp_body.is_empty() {
            out.push_str(&String::from_utf8_lossy(&ex.resp_body));
            if ex.resp_body_truncated {
                out.push_str("\n[...truncated...]");
            }
            out.push('\n');
        }
        out.push('\n');
    }
    out
}

/// Serialize captured exchanges to a Postman collection (v2.1).
pub fn to_postman(exchanges: &[StoredExchange]) -> String {
    let items: Vec<Value> = exchanges.iter().map(postman_item).collect();
    let doc = json!({
        "info": {
            "name": "Abyssum observed traffic",
            "description": "Captured by the Abyssum proxy (best-effort export).",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "_postman_id": format!("abyssum-{VERSION}"),
        },
        "item": items,
    });
    to_pretty(&doc)
}

/// One Postman `item[]` object for a stored exchange.
fn postman_item(row: &StoredExchange) -> Value {
    let ex = &row.exchange;
    let header: Vec<Value> = ex
        .req_headers
        .iter()
        .map(|(k, v)| json!({ "key": k, "value": v }))
        .collect();
    let mut request = json!({
        "method": ex.method,
        "header": header,
        "url": { "raw": ex.url },
    });
    if !ex.req_body.is_empty() {
        request["body"] = json!({
            "mode": "raw",
            "raw": String::from_utf8_lossy(&ex.req_body),
        });
    }
    json!({
        "name": format!("{} {}", ex.method, ex.endpoint),
        "request": request,
    })
}

// --- shared helpers ---------------------------------------------------------

/// A best-effort path template plus its parameter names: numeric or UUID segments
/// become `{id}`, `{id2}`, … so distinct object references collapse to one path.
fn path_template(endpoint: &str) -> (String, Vec<String>) {
    let mut params = Vec::new();
    let templated: Vec<String> = endpoint
        .split('/')
        .map(|seg| {
            if crate::analysis::is_ref_segment(seg) {
                let name = if params.is_empty() {
                    "id".to_string()
                } else {
                    format!("id{}", params.len() + 1)
                };
                params.push(name.clone());
                format!("{{{name}}}")
            } else {
                seg.to_string()
            }
        })
        .collect();
    (templated.join("/"), params)
}

/// A JSON example from a body: the parsed JSON when the body is JSON, else the
/// UTF-8 (lossy) text. Returns the media type to key the example under.
fn body_example(headers: &[(String, String)], body: &[u8]) -> (String, Value) {
    let ct = content_type(headers).unwrap_or("application/octet-stream");
    if ct.contains("json")
        && let Ok(value) = serde_json::from_slice::<Value>(body)
    {
        return (ct.to_string(), value);
    }
    (
        ct.to_string(),
        Value::String(String::from_utf8_lossy(body).into_owned()),
    )
}

/// The `Content-Type` media type (without parameters), if present.
fn content_type(headers: &[(String, String)]) -> Option<&str> {
    header_value(headers, "content-type").map(|v| v.split(';').next().unwrap_or(v).trim())
}

/// The `Location` response header, if present.
fn location(headers: &[(String, String)]) -> Option<String> {
    header_value(headers, "location").map(str::to_string)
}

/// The first value of the header named `name` (case-insensitive).
fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// The origin-form request target (`/path?query`) reconstructed from a full URL,
/// for the raw request line. Falls back to the whole URL if it can't be split.
fn request_target(url: &str) -> String {
    // Skip scheme://authority to the first '/' of the path.
    if let Some(scheme_end) = url.find("://") {
        let after = &url[scheme_end + 3..];
        if let Some(slash) = after.find('/') {
            return after[slash..].to_string();
        }
        return "/".to_string();
    }
    url.to_string()
}

/// Split a raw query string into (name, value) pairs (value empty when absent).
fn query_pairs(query: Option<&str>) -> Vec<(String, String)> {
    let Some(query) = query else {
        return Vec::new();
    };
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (pair.to_string(), String::new()),
        })
        .collect()
}

/// Pretty-print a JSON value, falling back to a minimal valid document if
/// serialization somehow fails (it never does for the values we build).
fn to_pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::CapturedExchange;
    use chrono::Utc;

    /// Build a stored exchange for export tests.
    #[allow(clippy::too_many_arguments)]
    fn stored(
        id: i64,
        method: &str,
        url: &str,
        endpoint: &str,
        query: Option<&str>,
        params: &[&str],
        req_body: &[u8],
        status: u16,
        resp_ct: &str,
        resp_body: &[u8],
    ) -> StoredExchange {
        StoredExchange {
            id,
            exchange: CapturedExchange {
                method: method.into(),
                url: url.into(),
                host: "api.test".into(),
                endpoint: endpoint.into(),
                query: query.map(str::to_string),
                params: params.iter().map(|p| p.to_string()).collect(),
                req_headers: vec![("content-type".into(), "application/json".into())],
                req_body: req_body.to_vec(),
                req_body_truncated: false,
                status,
                resp_headers: vec![("content-type".into(), resp_ct.into())],
                resp_body: resp_body.to_vec(),
                resp_body_truncated: false,
                started_at: Utc::now(),
                duration_ms: 7,
            },
            flags: Vec::new(),
            score: 0,
        }
    }

    fn sample_set() -> Vec<StoredExchange> {
        vec![
            stored(
                1,
                "GET",
                "https://api.test/api/users/1?expand=roles",
                "/api/users/1",
                Some("expand=roles"),
                &["expand"],
                b"",
                200,
                "application/json",
                br#"{"id":1,"name":"a"}"#,
            ),
            stored(
                2,
                "GET",
                "https://api.test/api/users/2",
                "/api/users/2",
                None,
                &[],
                b"",
                200,
                "application/json",
                br#"{"id":2,"name":"b"}"#,
            ),
            stored(
                3,
                "POST",
                "https://api.test/api/orders",
                "/api/orders",
                None,
                &[],
                br#"{"item":"x"}"#,
                201,
                "application/json",
                br#"{"ok":true}"#,
            ),
        ]
    }

    #[test]
    fn har_has_expected_shape() {
        let har: Value = serde_json::from_str(&to_har(&sample_set())).unwrap();
        assert_eq!(har["log"]["version"], "1.2");
        let entries = har["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0]["request"]["method"], "GET");
        assert_eq!(entries[0]["response"]["status"], 200);
        // The query parameter is surfaced in the HAR queryString.
        assert_eq!(entries[0]["request"]["queryString"][0]["name"], "expand");
        // A request body becomes postData (the POST /api/orders exchange).
        assert!(
            entries[2]["request"]["postData"]["text"]
                .as_str()
                .unwrap()
                .contains("item")
        );
    }

    #[test]
    fn openapi_groups_by_method_and_path_template_and_is_best_effort() {
        let oas: Value = serde_json::from_str(&to_openapi(&sample_set())).unwrap();
        assert_eq!(oas["openapi"], "3.0.3");
        // Best-effort disclaimer is present.
        assert!(
            oas["info"]["description"]
                .as_str()
                .unwrap()
                .to_ascii_uppercase()
                .contains("BEST-EFFORT")
        );
        let paths = oas["paths"].as_object().unwrap();
        // /api/users/1 and /api/users/2 collapse to one templated path.
        assert!(paths.contains_key("/api/users/{id}"), "paths: {paths:?}");
        assert!(paths.contains_key("/api/orders"));
        // The templated path carries a path parameter and the observed query param.
        let get = &paths["/api/users/{id}"]["get"];
        let param_names: Vec<&str> = get["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        assert!(param_names.contains(&"id"));
        assert!(param_names.contains(&"expand"));
        // A 200 response with a JSON example is recorded.
        assert!(
            get["responses"]["200"]["content"]["application/json"]["example"]["id"].is_number()
        );
        // The POST carries a requestBody example.
        assert_eq!(
            paths["/api/orders"]["post"]["requestBody"]["content"]["application/json"]["example"]["item"],
            "x"
        );
    }

    #[test]
    fn raw_emits_verbatim_request_and_response() {
        let raw = to_raw(&sample_set());
        assert!(raw.contains("===== Exchange 1 ====="));
        assert!(raw.contains("GET /api/users/1?expand=roles HTTP/1.1"));
        assert!(raw.contains("HTTP/1.1 200"));
        assert!(raw.contains(r#"{"id":1,"name":"a"}"#));
        // The POST body is present verbatim.
        assert!(raw.contains(r#"{"item":"x"}"#));
    }

    #[test]
    fn postman_collection_has_expected_shape() {
        let pm: Value = serde_json::from_str(&to_postman(&sample_set())).unwrap();
        assert!(pm["info"]["schema"].as_str().unwrap().contains("v2.1.0"));
        let items = pm["item"].as_array().unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0]["request"]["method"], "GET");
        assert_eq!(items[2]["request"]["body"]["mode"], "raw");
    }

    #[test]
    fn format_names_round_trip() {
        assert_eq!(ExportFormat::from_name("HAR"), Some(ExportFormat::Har));
        assert_eq!(
            ExportFormat::from_name("openapi"),
            Some(ExportFormat::OpenApi)
        );
        assert_eq!(ExportFormat::from_name("raw"), Some(ExportFormat::Raw));
        assert_eq!(
            ExportFormat::from_name("postman"),
            Some(ExportFormat::Postman)
        );
        assert_eq!(ExportFormat::from_name("nope"), None);
    }

    #[test]
    fn path_template_collapses_ids_and_uuids() {
        assert_eq!(path_template("/users/123").0, "/users/{id}");
        assert_eq!(
            path_template("/orders/550e8400-e29b-41d4-a716-446655440000/items").0,
            "/orders/{id}/items"
        );
        // A plain word segment is left alone.
        assert_eq!(path_template("/users/profile").0, "/users/profile");
        // Two id segments get distinct parameter names.
        let (tmpl, params) = path_template("/a/1/b/2");
        assert_eq!(tmpl, "/a/{id}/b/{id2}");
        assert_eq!(params, vec!["id".to_string(), "id2".to_string()]);
    }
}
