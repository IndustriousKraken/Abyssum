//! The captured response and the overall request outcome.
//!
//! [`CapturedResponse`] holds the response read off the wire — status, headers,
//! the body, timing, and the redirect outcome (final URL plus a hop count). The
//! body is read up to a configured byte cap (marked via
//! [`body_truncated`](CapturedResponse::body_truncated) when the cap is hit) so a
//! hostile or misconfigured target cannot exhaust memory; the retained body is what
//! [`analyze`](super::analyze) scans. The rendered preview is truncated to a
//! tighter cap at display time ([`CapturedResponse::display_body`]) so neither
//! output form carries an unbounded payload.

use std::time::Duration;

use super::analysis::Signal;
use super::spec::PreparedRequest;

/// Everything captured from a completed response.
#[derive(Debug, Clone)]
pub struct CapturedResponse {
    /// Final HTTP status (after any followed redirects).
    pub status: u16,
    /// Response headers, in arrival order.
    pub headers: Vec<(String, String)>,
    /// The response body (decoded lossily as UTF-8), read up to the configured
    /// byte cap. When the cap was hit this holds only the captured prefix; see
    /// [`body_truncated`](Self::body_truncated).
    pub body: String,
    /// Round-trip elapsed time, from just before send to body fully read.
    pub elapsed: Duration,
    /// The final URL after following redirects (the requested URL when none were
    /// followed).
    pub final_url: String,
    /// The number of redirects followed (`0` when redirect-following is off or the
    /// target did not redirect).
    pub redirect_count: usize,
    /// Whether the body was truncated during the read because the response exceeded
    /// the configured byte cap. When `true`, both the stored [`body`](Self::body)
    /// and any analysis over it cover only the captured prefix of the response.
    pub body_truncated: bool,
}

impl CapturedResponse {
    /// The response `Content-Type`, if present.
    pub fn content_type(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
    }

    /// Whether the response declares a JSON content type.
    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|ct| ct.to_ascii_lowercase().contains("json"))
            .unwrap_or(false)
    }

    /// The body rendered for display: pretty-printed when the response declares a
    /// JSON content type and the body parses as JSON, then truncated to `cap`
    /// bytes. Returns the (possibly truncated) text and whether truncation
    /// occurred.
    pub fn display_body(&self, cap: usize) -> (String, bool) {
        let text = if self.is_json() {
            match serde_json::from_str::<serde_json::Value>(&self.body) {
                Ok(value) => {
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| self.body.clone())
                }
                Err(_) => self.body.clone(),
            }
        } else {
            self.body.clone()
        };
        truncate(text, cap)
    }
}

/// Truncate `text` to at most `cap` bytes on a char boundary, reporting whether it
/// was shortened.
fn truncate(text: String, cap: usize) -> (String, bool) {
    if text.len() <= cap {
        return (text, false);
    }
    let mut end = cap;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

/// The send result: a captured response, or a transport/timeout error message.
///
/// A transport failure is reported here rather than panicking, so a single bad
/// request never crashes the surrounding process.
#[derive(Debug, Clone)]
pub enum CaptureResult {
    /// The request completed and the response was captured.
    Response(CapturedResponse),
    /// The request failed at the transport layer (DNS, connection, TLS, timeout) or
    /// was halted by the pacing layer. Carries the operator-facing message.
    Error(String),
}

/// One tool invocation's full result: the echoed request, the send result, and the
/// advisory analysis signals. Rendered to human or JSON form by
/// [`render`](super::OutputFormat) / [`RequestOutcome::render`].
#[derive(Debug, Clone)]
pub struct RequestOutcome {
    /// The request as actually resolved and sent (the echo).
    pub request: PreparedRequest,
    /// The captured response, or the error if the request failed.
    pub result: CaptureResult,
    /// Advisory security signals from analyzing the response (empty on error).
    pub signals: Vec<Signal>,
    /// Byte cap applied to the rendered body preview.
    pub body_preview_cap: usize,
}

impl RequestOutcome {
    /// The captured response, if the request succeeded.
    pub fn response(&self) -> Option<&CapturedResponse> {
        match &self.result {
            CaptureResult::Response(r) => Some(r),
            CaptureResult::Error(_) => None,
        }
    }

    /// The error message, if the request failed.
    pub fn error(&self) -> Option<&str> {
        match &self.result {
            CaptureResult::Error(e) => Some(e.as_str()),
            CaptureResult::Response(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(content_type: &str, body: &str) -> CapturedResponse {
        CapturedResponse {
            status: 200,
            headers: vec![("content-type".to_string(), content_type.to_string())],
            body: body.to_string(),
            elapsed: Duration::from_millis(5),
            final_url: "https://x.test/".to_string(),
            redirect_count: 0,
            body_truncated: false,
        }
    }

    #[test]
    fn is_json_detects_json_content_types() {
        assert!(resp("application/json", "{}").is_json());
        assert!(resp("application/ld+json; charset=utf-8", "{}").is_json());
        assert!(!resp("text/html", "<html>").is_json());
    }

    #[test]
    fn display_body_pretty_prints_json() {
        let (text, truncated) =
            resp("application/json", r#"{"a":1,"b":2}"#).display_body(64 * 1024);
        assert!(!truncated);
        // Pretty-printing introduces newlines and indentation.
        assert!(text.contains('\n'));
        assert!(text.contains("\"a\": 1"));
    }

    #[test]
    fn display_body_leaves_non_json_verbatim() {
        let (text, _) = resp("text/plain", "hello world").display_body(64 * 1024);
        assert_eq!(text, "hello world");
    }

    #[test]
    fn display_body_truncates_and_marks() {
        let big = "x".repeat(100);
        let (text, truncated) = resp("text/plain", &big).display_body(10);
        assert!(truncated);
        assert_eq!(text.len(), 10);
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        // A 4-byte char straddling the cap is dropped rather than split.
        let s = "aaa😀".to_string(); // 3 + 4 bytes
        let (text, truncated) = truncate(s, 5);
        assert!(truncated);
        assert_eq!(text, "aaa");
    }
}
