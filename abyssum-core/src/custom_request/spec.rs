//! The custom-request specification and the pure steps that resolve it.
//!
//! A [`CustomRequestSpec`] is the operator's raw input: a URL, a method, custom
//! headers, an optional body, and optional bearer/cookie auth. Turning it into the
//! request actually sent — normalizing the URL and method, folding in the
//! `Authorization`/`Cookie`/`Content-Type` headers — is pure and side-effect free
//! ([`CustomRequestSpec::prepare`]), so auth assembly and JSON body detection are
//! unit-testable without ever touching the network.

use std::time::Duration;

use serde::Serialize;
use url::Url;

/// Default round-trip timeout for a single custom request.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default cap on the rendered response-body preview (64 KB). Larger bodies are
/// shown up to this size and marked truncated; analysis still scans the full
/// captured body (itself bounded by [`DEFAULT_MAX_BODY_BYTES`]).
pub const DEFAULT_BODY_PREVIEW_CAP: usize = 64 * 1024;

/// Default cap on the number of response-body bytes read into memory (8 MiB). A
/// larger response is read up to this bound and marked truncated, so a hostile or
/// misconfigured target cannot exhaust process memory with a multi-gigabyte body.
/// This bounds both the stored body and what [`analyze`](super::analyze) scans; the
/// rendered preview is capped separately and more tightly by
/// [`DEFAULT_BODY_PREVIEW_CAP`].
pub const DEFAULT_MAX_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Maximum redirect hops followed when `follow_redirects` is set.
pub(crate) const MAX_REDIRECTS: usize = 10;

/// What the operator asked the tool to send.
///
/// Auth is **additive and optional**: a spec with neither a [`bearer`] token nor a
/// [`cookie`] string is a first-class keyless request and is sent with no added
/// authentication. TLS verification defaults **on**; it is relaxed only by setting
/// [`verify_tls`] to `false` for that single invocation.
///
/// [`bearer`]: Self::bearer
/// [`cookie`]: Self::cookie
/// [`verify_tls`]: Self::verify_tls
#[derive(Debug, Clone)]
pub struct CustomRequestSpec {
    /// Target URL as typed by the operator (normalized on [`prepare`](Self::prepare)).
    pub url: String,
    /// HTTP method as typed (uppercased on prepare; empty defaults to `GET`).
    pub method: String,
    /// Extra request headers, in order.
    pub headers: Vec<(String, String)>,
    /// Optional request body.
    pub body: Option<String>,
    /// Explicit content type. When unset and a body is present that parses as JSON,
    /// the content type defaults to `application/json`; otherwise the body is sent
    /// verbatim with no content type added.
    pub content_type: Option<String>,
    /// Optional bearer token, sent as `Authorization: Bearer <token>`. Supersedes a
    /// custom `Authorization` header when both are present.
    pub bearer: Option<String>,
    /// Optional `Cookie:` header value.
    pub cookie: Option<String>,
    /// Whether to follow redirect hops (default `false`).
    pub follow_redirects: bool,
    /// Whether to verify the target's TLS certificate (default `true`).
    pub verify_tls: bool,
    /// Round-trip timeout for the request.
    pub timeout: Duration,
    /// Byte cap on the rendered response-body preview.
    pub body_preview_cap: usize,
    /// Maximum number of response-body bytes read into memory. A larger response is
    /// truncated at this cap (and the capture marked truncated) so a single request
    /// cannot exhaust process memory.
    pub max_body_bytes: usize,
}

impl Default for CustomRequestSpec {
    fn default() -> Self {
        Self {
            url: String::new(),
            method: "GET".to_string(),
            headers: Vec::new(),
            body: None,
            content_type: None,
            bearer: None,
            cookie: None,
            follow_redirects: false,
            verify_tls: true,
            timeout: DEFAULT_TIMEOUT,
            body_preview_cap: DEFAULT_BODY_PREVIEW_CAP,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

impl CustomRequestSpec {
    /// A GET request for `url` with default settings (TLS verification on, no
    /// redirect following, no auth).
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Self::default()
        }
    }

    /// Set the HTTP method (builder-style).
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }

    /// Add a custom header (builder-style).
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the request body (builder-style).
    pub fn body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Set an explicit content type (builder-style).
    pub fn content_type(mut self, ct: impl Into<String>) -> Self {
        self.content_type = Some(ct.into());
        self
    }

    /// Attach a bearer token (builder-style).
    pub fn bearer(mut self, token: impl Into<String>) -> Self {
        self.bearer = Some(token.into());
        self
    }

    /// Attach a cookie string (builder-style).
    pub fn cookie(mut self, cookie: impl Into<String>) -> Self {
        self.cookie = Some(cookie.into());
        self
    }

    /// Set whether redirects are followed (builder-style).
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.follow_redirects = follow;
        self
    }

    /// Set whether the TLS certificate is verified (builder-style). Passing `false`
    /// is the `--insecure` / `--no-verify-tls` opt-out, scoped to this request.
    pub fn verify_tls(mut self, verify: bool) -> Self {
        self.verify_tls = verify;
        self
    }

    /// Set the round-trip timeout (builder-style).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum number of response-body bytes read into memory
    /// (builder-style). A larger response is truncated at this cap and the capture
    /// is marked truncated.
    pub fn max_body_bytes(mut self, max: usize) -> Self {
        self.max_body_bytes = max;
        self
    }

    /// Resolve the spec into the concrete request to send: a normalized method and
    /// URL plus the full header set with `Authorization`/`Cookie`/`Content-Type`
    /// folded in. Returns the operator-facing error string when the URL is
    /// unparseable.
    pub(crate) fn prepare(&self) -> Result<PreparedRequest, String> {
        let url = normalize_url(&self.url)?;
        Ok(PreparedRequest {
            method: normalize_method(&self.method),
            url: url.to_string(),
            headers: self.assemble_headers(),
            body: self.body.clone(),
        })
    }

    /// A best-effort echo of the request when [`prepare`](Self::prepare) fails
    /// (only the URL can fail to normalize): the raw URL string is preserved so the
    /// error output still shows what was attempted.
    pub(crate) fn raw_echo(&self) -> PreparedRequest {
        PreparedRequest {
            method: normalize_method(&self.method),
            url: self.url.clone(),
            headers: self.assemble_headers(),
            body: self.body.clone(),
        }
    }

    /// Build the final header list actually sent.
    ///
    /// Folds in, in order: the resolved content type (explicit, or auto-detected
    /// JSON), the bearer `Authorization` header (superseding any custom one), and
    /// the `Cookie` header. When neither a token nor a cookie is supplied, no auth
    /// header is added — the request goes out keyless.
    pub(crate) fn assemble_headers(&self) -> Vec<(String, String)> {
        let mut headers = self.headers.clone();

        // Content type: an explicit type wins and replaces any custom Content-Type
        // header. Otherwise, only auto-detect JSON when the operator did not set a
        // Content-Type header themselves (respect a verbatim choice).
        if let Some(ct) = &self.content_type {
            set_header(&mut headers, "Content-Type", ct);
        } else if !has_header(&headers, "content-type") {
            if let Some(body) = &self.body {
                if looks_like_json(body) {
                    headers.push(("Content-Type".to_string(), "application/json".to_string()));
                }
            }
        }

        // A supplied bearer token supersedes any custom Authorization header.
        if let Some(token) = &self.bearer {
            remove_header(&mut headers, "authorization");
            headers.push(("Authorization".to_string(), bearer_header_value(token)));
        }

        // A supplied cookie string supersedes any custom Cookie header.
        if let Some(cookie) = &self.cookie {
            remove_header(&mut headers, "cookie");
            headers.push(("Cookie".to_string(), cookie.clone()));
        }

        headers
    }
}

/// The fully-resolved request actually sent. Serialized as the request echo in the
/// JSON output document; `url` is the normalized string (or the raw string when
/// normalization failed).
#[derive(Debug, Clone, Serialize)]
pub struct PreparedRequest {
    /// Normalized, uppercased HTTP method.
    pub method: String,
    /// Normalized target URL.
    pub url: String,
    /// The complete header set, with auth and content type folded in.
    pub headers: Vec<(String, String)>,
    /// The request body, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// Normalize a typed URL: trim it, and prepend `https://` when it carries no
/// scheme, so a bare `example.com:8080` is not mis-parsed (its host becoming a
/// "scheme"). Returns an error string for an empty or unparseable URL.
///
/// Public so a surface can vet the *exact* host the tool will contact (e.g. the
/// web SSRF guard) using this same normalization, rather than re-deriving it.
pub fn normalize_url(raw: &str) -> Result<Url, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("URL is empty".to_string());
    }
    let candidate = if has_scheme(trimmed) {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    Url::parse(&candidate).map_err(|e| format!("invalid URL {raw:?}: {e}"))
}

/// Whether `s` begins with an explicit URL scheme (`scheme://`).
fn has_scheme(s: &str) -> bool {
    match s.find("://") {
        Some(idx) if idx > 0 => {
            let scheme = &s[..idx];
            scheme.starts_with(|c: char| c.is_ascii_alphabetic())
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        }
        _ => false,
    }
}

/// Uppercase the method, defaulting an empty value to `GET`.
pub(crate) fn normalize_method(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        "GET".to_string()
    } else {
        trimmed.to_ascii_uppercase()
    }
}

/// Build the `Authorization` value for a bearer token without double-prefixing a
/// value the operator already prefixed with `Bearer `.
fn bearer_header_value(token: &str) -> String {
    let token = token.trim();
    if token
        .get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("bearer "))
    {
        token.to_string()
    } else {
        format!("Bearer {token}")
    }
}

/// Whether a body should be treated as JSON for content-type auto-detection: it
/// looks structurally like JSON (object/array) and parses cleanly. A bare scalar
/// such as `5` or `form=value` is intentionally not treated as JSON.
pub(crate) fn looks_like_json(body: &str) -> bool {
    let trimmed = body.trim_start();
    (trimmed.starts_with('{') || trimmed.starts_with('['))
        && serde_json::from_str::<serde_json::Value>(body).is_ok()
}

fn has_header(headers: &[(String, String)], name: &str) -> bool {
    headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
}

fn remove_header(headers: &mut Vec<(String, String)>, name: &str) {
    headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
}

fn set_header(headers: &mut Vec<(String, String)>, name: &str, value: &str) {
    remove_header(headers, name);
    headers.push((name.to_string(), value.to_string()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn count(headers: &[(String, String)], name: &str) -> usize {
        headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .count()
    }

    // --- Task 1.2: method/URL normalization ---------------------------------

    #[test]
    fn method_uppercases_and_defaults_to_get() {
        assert_eq!(normalize_method("get"), "GET");
        assert_eq!(normalize_method("Post"), "POST");
        assert_eq!(normalize_method("   "), "GET");
        assert_eq!(normalize_method(""), "GET");
    }

    #[test]
    fn url_without_scheme_gets_https() {
        let u = normalize_url("example.com/api").unwrap();
        assert_eq!(u.as_str(), "https://example.com/api");
    }

    #[test]
    fn url_with_port_but_no_scheme_is_not_misparsed() {
        // Without the https prefix, `example.com:8080` parses with `example.com`
        // mistaken for the scheme. Normalization prevents that.
        let u = normalize_url("example.com:8080/x").unwrap();
        assert_eq!(u.host_str(), Some("example.com"));
        assert_eq!(u.port(), Some(8080));
    }

    #[test]
    fn url_keeps_explicit_scheme() {
        assert_eq!(
            normalize_url("http://example.com/").unwrap().as_str(),
            "http://example.com/"
        );
    }

    #[test]
    fn empty_url_is_an_error() {
        assert!(normalize_url("   ").is_err());
    }

    // --- Task 5.1: auth assembly (token-only, cookie-only, both, neither) ----

    #[test]
    fn auth_token_only_adds_bearer_no_cookie() {
        let h = CustomRequestSpec::new("https://x.test")
            .bearer("abc123")
            .assemble_headers();
        assert_eq!(find(&h, "authorization"), Some("Bearer abc123"));
        assert!(find(&h, "cookie").is_none());
    }

    #[test]
    fn auth_cookie_only_adds_cookie_no_bearer() {
        let h = CustomRequestSpec::new("https://x.test")
            .cookie("session=deadbeef")
            .assemble_headers();
        assert_eq!(find(&h, "cookie"), Some("session=deadbeef"));
        assert!(find(&h, "authorization").is_none());
    }

    #[test]
    fn auth_both_adds_both() {
        let h = CustomRequestSpec::new("https://x.test")
            .bearer("tok")
            .cookie("a=b")
            .assemble_headers();
        assert_eq!(find(&h, "authorization"), Some("Bearer tok"));
        assert_eq!(find(&h, "cookie"), Some("a=b"));
    }

    #[test]
    fn auth_neither_is_keyless() {
        let h = CustomRequestSpec::new("https://x.test").assemble_headers();
        assert!(find(&h, "authorization").is_none());
        assert!(find(&h, "cookie").is_none());
    }

    // --- Task 1.3: bearer prefixing and supersession ------------------------

    #[test]
    fn bearer_value_is_not_double_prefixed() {
        assert_eq!(bearer_header_value("xyz"), "Bearer xyz");
        assert_eq!(bearer_header_value("Bearer xyz"), "Bearer xyz");
        // Case-insensitive on the existing prefix.
        assert_eq!(bearer_header_value("bearer xyz"), "bearer xyz");
    }

    #[test]
    fn bearer_value_is_total_on_non_ascii_input() {
        // A token whose byte 7 falls inside a multi-byte char: `aaaa` (4 bytes)
        // then a 4-byte emoji spanning bytes 4..8, so byte index 7 is not a char
        // boundary. A byte-index slice `token[..7]` would panic here; `get(..7)`
        // returns None and the value is simply prefixed.
        assert_eq!(bearer_header_value("aaaa\u{1F600}"), "Bearer aaaa\u{1F600}");
    }

    #[test]
    fn bearer_supersedes_custom_authorization_header() {
        let h = CustomRequestSpec::new("https://x.test")
            .header("Authorization", "Basic Zm9vOmJhcg==")
            .bearer("realtoken")
            .assemble_headers();
        assert_eq!(count(&h, "authorization"), 1);
        assert_eq!(find(&h, "authorization"), Some("Bearer realtoken"));
    }

    #[test]
    fn custom_authorization_kept_when_no_bearer() {
        let h = CustomRequestSpec::new("https://x.test")
            .header("Authorization", "Basic Zm9vOmJhcg==")
            .assemble_headers();
        assert_eq!(find(&h, "authorization"), Some("Basic Zm9vOmJhcg=="));
    }

    // --- Task 1.6 / 5.3: JSON body auto-detection vs. verbatim --------------

    #[test]
    fn json_body_autodetects_content_type() {
        assert!(looks_like_json(r#"{"a":1}"#));
        assert!(looks_like_json("  [1, 2, 3]"));
        let h = CustomRequestSpec::new("https://x.test")
            .body(r#"{"a":1}"#)
            .assemble_headers();
        assert_eq!(find(&h, "content-type"), Some("application/json"));
    }

    #[test]
    fn non_json_body_is_sent_verbatim_without_content_type() {
        assert!(!looks_like_json("user=admin&id=1"));
        assert!(!looks_like_json("5"));
        assert!(!looks_like_json("plain text"));
        let h = CustomRequestSpec::new("https://x.test")
            .body("user=admin&id=1")
            .assemble_headers();
        assert!(find(&h, "content-type").is_none());
    }

    #[test]
    fn explicit_content_type_wins_over_autodetect() {
        let h = CustomRequestSpec::new("https://x.test")
            .body(r#"{"a":1}"#)
            .content_type("text/plain")
            .assemble_headers();
        assert_eq!(count(&h, "content-type"), 1);
        assert_eq!(find(&h, "content-type"), Some("text/plain"));
    }

    #[test]
    fn custom_content_type_header_suppresses_autodetect() {
        let h = CustomRequestSpec::new("https://x.test")
            .header("Content-Type", "application/xml")
            .body(r#"{"a":1}"#)
            .assemble_headers();
        assert_eq!(count(&h, "content-type"), 1);
        assert_eq!(find(&h, "content-type"), Some("application/xml"));
    }

    #[test]
    fn prepare_normalizes_method_and_url() {
        let prepared = CustomRequestSpec::new("example.com/p")
            .method("post")
            .prepare()
            .unwrap();
        assert_eq!(prepared.method, "POST");
        assert_eq!(prepared.url, "https://example.com/p");
    }

    #[test]
    fn prepare_fails_on_bad_url_but_raw_echo_survives() {
        let spec = CustomRequestSpec::new("   ").method("get");
        assert!(spec.prepare().is_err());
        let echo = spec.raw_echo();
        assert_eq!(echo.method, "GET");
        assert_eq!(echo.url, "   ");
    }
}
