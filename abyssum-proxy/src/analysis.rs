//! Off-hot-path analysis of captured exchanges.
//!
//! [`analyze`] inspects a stored exchange and auto-flags the security-relevant
//! elements a triager cares about — authentication material, object-reference /
//! pagination parameters (IDOR candidates), API endpoints, and server errors —
//! then sums an additive [interest score](Analysis::score) from the categories
//! present. It is a pure function run over the **stored** exchange (in the async
//! writer, see [`TrafficStore::record`](crate::store::TrafficStore::record)),
//! never inline in the relay path — so it can never affect the proxy's
//! non-blocking behaviour.
//!
//! The categories deliberately mirror the scanners' finding classes so surfaced
//! traffic can later hand IDOR / endpoint candidates to the scanner. The score is
//! a ranking aid, not a verdict (see `design.md`).

use crate::store::CapturedExchange;

/// A security-relevant category auto-detected in a captured exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    /// Authentication material: an `Authorization` header, a `Cookie`/`Set-Cookie`,
    /// or a token-shaped parameter.
    Auth,
    /// An object-reference / pagination parameter or id-shaped path segment — an
    /// IDOR candidate.
    Idor,
    /// An API endpoint: a `/api` or versioned path, GraphQL, or a JSON response.
    Api,
    /// A server-error (5xx) response.
    Error,
}

impl Flag {
    /// The stable lowercase label persisted with the exchange and used in queries.
    pub fn label(self) -> &'static str {
        match self {
            Flag::Auth => "auth",
            Flag::Idor => "idor",
            Flag::Api => "api",
            Flag::Error => "error",
        }
    }

    /// Parse a persisted [`label`](Self::label) back into a flag; unknown → `None`.
    pub fn from_label(s: &str) -> Option<Flag> {
        match s {
            "auth" => Some(Flag::Auth),
            "idor" => Some(Flag::Idor),
            "api" => Some(Flag::Api),
            "error" => Some(Flag::Error),
            _ => None,
        }
    }

    /// The additive interest weight this category contributes. Auth and IDOR
    /// candidates weigh heaviest; a bare API endpoint is the mildest signal.
    fn weight(self) -> i64 {
        match self {
            Flag::Auth => 3,
            Flag::Idor => 3,
            Flag::Error => 2,
            Flag::Api => 1,
        }
    }
}

/// The result of analysing one exchange: the categories present and their summed
/// interest score. A ranking aid, not a verdict.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Analysis {
    /// The security-relevant categories detected, in a stable order.
    pub flags: Vec<Flag>,
    /// The additive interest score (sum of the present categories' weights).
    pub score: i64,
}

/// Analyse a captured exchange: detect the security-relevant categories and sum
/// their weights into an additive interest score.
pub fn analyze(ex: &CapturedExchange) -> Analysis {
    let mut flags = Vec::new();
    if is_auth(ex) {
        flags.push(Flag::Auth);
    }
    if is_idor(ex) {
        flags.push(Flag::Idor);
    }
    if is_api(ex) {
        flags.push(Flag::Api);
    }
    if ex.status >= 500 {
        flags.push(Flag::Error);
    }
    let score = flags.iter().map(|f| f.weight()).sum();
    Analysis { flags, score }
}

/// Parameter names that look like an auth token or secret.
const TOKEN_PARAMS: &[&str] = &[
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "key",
    "secret",
    "session",
    "sessionid",
    "sid",
    "jwt",
    "sig",
    "signature",
    "password",
    "passwd",
    "pwd",
];

/// Object-reference / pagination parameter names — IDOR candidates.
const REF_PARAMS: &[&str] = &[
    "id",
    "uid",
    "user_id",
    "userid",
    "account_id",
    "object_id",
    "order_id",
    "page",
    "offset",
    "cursor",
    "start",
    "per_page",
    "page_size",
    "size",
];

/// Auth material: an `Authorization`/`Cookie` request header, a `Set-Cookie`
/// response header, or a token-shaped parameter.
fn is_auth(ex: &CapturedExchange) -> bool {
    has_header(&ex.req_headers, "authorization")
        || has_header(&ex.req_headers, "cookie")
        || has_header(&ex.resp_headers, "set-cookie")
        || ex
            .params
            .iter()
            .any(|p| TOKEN_PARAMS.contains(&p.to_ascii_lowercase().as_str()))
}

/// IDOR candidate: an object-reference / pagination parameter (or one ending in
/// `_id`), or an id-shaped path segment (all-digit or UUID).
fn is_idor(ex: &CapturedExchange) -> bool {
    ex.params.iter().any(|p| {
        let p = p.to_ascii_lowercase();
        REF_PARAMS.contains(&p.as_str()) || p.ends_with("_id")
    }) || ex.endpoint.split('/').any(is_ref_segment)
}

/// API endpoint: an `api`/`graphql`/`v<N>` path segment, or a JSON response.
fn is_api(ex: &CapturedExchange) -> bool {
    ex.endpoint.split('/').any(|seg| {
        seg.eq_ignore_ascii_case("api")
            || seg.eq_ignore_ascii_case("graphql")
            || is_version_segment(seg)
    }) || content_type_is_json(&ex.resp_headers)
}

/// Whether any header matches `name` case-insensitively.
fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name))
}

/// A path segment that looks like an object reference: all-digits or a UUID. The
/// single crate-wide definition — the OpenAPI path-templating in [`crate::export`]
/// reuses it so IDOR analysis and `{id}` collapsing agree on what a reference is.
pub(crate) fn is_ref_segment(seg: &str) -> bool {
    !seg.is_empty() && (seg.bytes().all(|b| b.is_ascii_digit()) || is_uuid(seg))
}

/// A canonical 8-4-4-4-12 hex UUID.
fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8usize, 4, 4, 4, 12])
            .all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A `v<N>` version segment (e.g. `v1`, `v2`).
fn is_version_segment(seg: &str) -> bool {
    seg.len() >= 2
        && (seg.as_bytes()[0] == b'v' || seg.as_bytes()[0] == b'V')
        && seg[1..].bytes().all(|b| b.is_ascii_digit())
}

/// Whether the `Content-Type` header names a JSON media type.
fn content_type_is_json(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("content-type") && v.to_ascii_lowercase().contains("json")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// Build an exchange for analysis tests. `ct` is the response content-type.
    fn ex(
        endpoint: &str,
        status: u16,
        params: &[&str],
        req_headers: &[(&str, &str)],
        ct: &str,
    ) -> CapturedExchange {
        CapturedExchange {
            method: "GET".into(),
            url: format!("https://api.test{endpoint}"),
            host: "api.test".into(),
            endpoint: endpoint.into(),
            query: None,
            params: params.iter().map(|p| p.to_string()).collect(),
            req_headers: req_headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            req_body: Vec::new(),
            req_body_truncated: false,
            status,
            resp_headers: vec![("content-type".into(), ct.into())],
            resp_body: Vec::new(),
            resp_body_truncated: false,
            started_at: Utc::now(),
            duration_ms: 1,
        }
    }

    #[test]
    fn auth_material_is_flagged() {
        // Authorization header.
        assert!(
            analyze(&ex(
                "/x",
                200,
                &[],
                &[("Authorization", "Bearer t")],
                "text/plain"
            ))
            .flags
            .contains(&Flag::Auth)
        );
        // Session cookie.
        assert!(
            analyze(&ex("/x", 200, &[], &[("Cookie", "sid=abc")], "text/plain"))
                .flags
                .contains(&Flag::Auth)
        );
        // Token-shaped parameter.
        assert!(
            analyze(&ex("/x", 200, &["access_token"], &[], "text/plain"))
                .flags
                .contains(&Flag::Auth)
        );
        // Nothing auth-y.
        assert!(
            !analyze(&ex("/x", 200, &["sort"], &[], "text/plain"))
                .flags
                .contains(&Flag::Auth)
        );
    }

    #[test]
    fn object_reference_params_and_segments_are_idor_candidates() {
        assert!(
            analyze(&ex("/users", 200, &["id"], &[], "text/plain"))
                .flags
                .contains(&Flag::Idor)
        );
        assert!(
            analyze(&ex("/users", 200, &["user_id"], &[], "text/plain"))
                .flags
                .contains(&Flag::Idor)
        );
        assert!(
            analyze(&ex("/users", 200, &["page"], &[], "text/plain"))
                .flags
                .contains(&Flag::Idor)
        );
        // Numeric path segment.
        assert!(
            analyze(&ex("/users/123", 200, &[], &[], "text/plain"))
                .flags
                .contains(&Flag::Idor)
        );
        // UUID path segment.
        assert!(
            analyze(&ex(
                "/orders/550e8400-e29b-41d4-a716-446655440000",
                200,
                &[],
                &[],
                "text/plain"
            ))
            .flags
            .contains(&Flag::Idor)
        );
        // A plain word segment is not an object reference.
        assert!(
            !analyze(&ex("/users/profile", 200, &[], &[], "text/plain"))
                .flags
                .contains(&Flag::Idor)
        );
    }

    #[test]
    fn api_endpoints_are_flagged() {
        assert!(
            analyze(&ex("/api/widgets", 200, &[], &[], "text/plain"))
                .flags
                .contains(&Flag::Api)
        );
        assert!(
            analyze(&ex("/v2/widgets", 200, &[], &[], "text/plain"))
                .flags
                .contains(&Flag::Api)
        );
        assert!(
            analyze(&ex("/graphql", 200, &[], &[], "text/plain"))
                .flags
                .contains(&Flag::Api)
        );
        // JSON response alone marks it an API.
        assert!(
            analyze(&ex("/data", 200, &[], &[], "application/json"))
                .flags
                .contains(&Flag::Api)
        );
        // A static asset is not an API.
        assert!(
            !analyze(&ex(
                "/static/app.js",
                200,
                &[],
                &[],
                "application/javascript"
            ))
            .flags
            .contains(&Flag::Api)
        );
    }

    #[test]
    fn server_errors_are_flagged() {
        assert!(
            analyze(&ex("/x", 500, &[], &[], "text/plain"))
                .flags
                .contains(&Flag::Error)
        );
        assert!(
            !analyze(&ex("/x", 404, &[], &[], "text/plain"))
                .flags
                .contains(&Flag::Error)
        );
    }

    #[test]
    fn score_is_additive_and_ranks_interesting_above_static() {
        // Auth token + numeric id in an API path: flagged in every relevant category.
        let hot = analyze(&ex(
            "/api/users/42",
            200,
            &["id"],
            &[("Authorization", "Bearer t")],
            "application/json",
        ));
        assert!(hot.flags.contains(&Flag::Auth));
        assert!(hot.flags.contains(&Flag::Idor));

        // A plain static asset: no categories, zero score.
        let cold = analyze(&ex(
            "/static/app.js",
            200,
            &[],
            &[],
            "application/javascript",
        ));
        assert_eq!(cold.score, 0);
        assert!(cold.flags.is_empty());

        assert!(hot.score > cold.score);
    }

    #[test]
    fn label_round_trips() {
        for f in [Flag::Auth, Flag::Idor, Flag::Api, Flag::Error] {
            assert_eq!(Flag::from_label(f.label()), Some(f));
        }
        assert_eq!(Flag::from_label("nope"), None);
    }
}
