//! Advisory response-signal analysis.
//!
//! [`analyze`] is a **pure** function over a captured response: no I/O, no network.
//! It surfaces notable security signals — information-disclosure headers, missing
//! response-hardening headers, and error-detail leakage in the body — as
//! *advisory hints* for manual follow-up. They are explicitly **not** confirmed
//! vulnerabilities and are never written to the findings store.

use serde::Serialize;

use super::response::CapturedResponse;

/// Headers whose mere presence discloses server software, technology stack, or
/// source-path information.
const DISCLOSURE_HEADERS: &[&str] = &[
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Debug",
    "X-SourceFiles",
];

/// Response-hardening headers whose *absence* is worth flagging.
const EXPECTED_SECURITY_HEADERS: &[&str] = &[
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
];

/// Body substrings suggesting a leaked stack trace / unhandled error.
const ERROR_DETAIL_KEYWORDS: &[&str] = &["traceback", "stack trace", "exception"];

/// Body substrings suggesting leaked debug/development detail.
const DEBUG_KEYWORDS: &[&str] = &["debug", "development", "localhost"];

/// The class of an advisory [`Signal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignalKind {
    /// A header disclosed server/technology/source-path information.
    InformationDisclosure,
    /// An expected response-hardening header was absent.
    MissingSecurityHeader,
    /// The body contained stack-trace / error indicators.
    ErrorDetailLeakage,
    /// The body contained debug/development indicators.
    DebugInformationLeakage,
}

impl SignalKind {
    /// A stable kebab-case label for human output.
    pub fn label(&self) -> &'static str {
        match self {
            SignalKind::InformationDisclosure => "information-disclosure",
            SignalKind::MissingSecurityHeader => "missing-security-header",
            SignalKind::ErrorDetailLeakage => "error-detail-leakage",
            SignalKind::DebugInformationLeakage => "debug-information-leakage",
        }
    }
}

/// One advisory signal: its class and a human-readable detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Signal {
    /// The class of signal.
    pub kind: SignalKind,
    /// Human-readable detail (e.g. the disclosing header and value, or the absent
    /// header name).
    pub detail: String,
}

/// Inspect a captured response and return the advisory signals it raises. A clean,
/// hardened response with no error detail yields an empty list.
pub fn analyze(response: &CapturedResponse) -> Vec<Signal> {
    let mut signals = Vec::new();

    // Information-disclosure headers that are present.
    for (name, value) in &response.headers {
        if DISCLOSURE_HEADERS
            .iter()
            .any(|h| h.eq_ignore_ascii_case(name))
        {
            signals.push(Signal {
                kind: SignalKind::InformationDisclosure,
                detail: format!("{name}: {value}"),
            });
        }
    }

    // Expected security headers that are absent.
    for expected in EXPECTED_SECURITY_HEADERS {
        let present = response
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(expected));
        if !present {
            signals.push(Signal {
                kind: SignalKind::MissingSecurityHeader,
                detail: (*expected).to_string(),
            });
        }
    }

    // Error-detail / debug leakage in the body.
    let body = response.body.to_ascii_lowercase();
    for keyword in ERROR_DETAIL_KEYWORDS {
        if body.contains(keyword) {
            signals.push(Signal {
                kind: SignalKind::ErrorDetailLeakage,
                detail: format!("response body contains {keyword:?}"),
            });
        }
    }
    for keyword in DEBUG_KEYWORDS {
        if body.contains(keyword) {
            signals.push(Signal {
                kind: SignalKind::DebugInformationLeakage,
                detail: format!("response body contains {keyword:?}"),
            });
        }
    }

    signals
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// All four expected security headers, so a test can isolate other signals.
    fn hardened_headers() -> Vec<(String, String)> {
        EXPECTED_SECURITY_HEADERS
            .iter()
            .map(|h| (h.to_string(), "x".to_string()))
            .collect()
    }

    fn response(headers: Vec<(String, String)>, body: &str) -> CapturedResponse {
        CapturedResponse {
            status: 200,
            headers,
            body: body.to_string(),
            elapsed: Duration::from_millis(1),
            final_url: "https://x.test/".to_string(),
            redirect_count: 0,
            body_truncated: false,
        }
    }

    fn kinds(signals: &[Signal]) -> Vec<SignalKind> {
        signals.iter().map(|s| s.kind).collect()
    }

    // --- Task 3.2 / 5.2: information-disclosure header ----------------------

    #[test]
    fn flags_disclosure_header_with_name_and_value() {
        let mut headers = hardened_headers();
        headers.push(("Server".to_string(), "nginx/1.25.1".to_string()));
        let signals = analyze(&response(headers, "ok"));
        let disclosure: Vec<_> = signals
            .iter()
            .filter(|s| s.kind == SignalKind::InformationDisclosure)
            .collect();
        assert_eq!(disclosure.len(), 1);
        assert!(disclosure[0].detail.contains("Server"));
        assert!(disclosure[0].detail.contains("nginx/1.25.1"));
    }

    #[test]
    fn flags_multiple_disclosure_headers() {
        let mut headers = hardened_headers();
        headers.push(("X-Powered-By".to_string(), "PHP/8.2".to_string()));
        headers.push(("X-AspNet-Version".to_string(), "4.0.30319".to_string()));
        let signals = analyze(&response(headers, "ok"));
        let n = signals
            .iter()
            .filter(|s| s.kind == SignalKind::InformationDisclosure)
            .count();
        assert_eq!(n, 2);
    }

    // --- Task 3.3 / 5.2: missing security headers ---------------------------

    #[test]
    fn flags_each_missing_security_header() {
        // No headers at all -> all four expected headers are flagged.
        let signals = analyze(&response(Vec::new(), "ok"));
        let missing: Vec<_> = signals
            .iter()
            .filter(|s| s.kind == SignalKind::MissingSecurityHeader)
            .collect();
        assert_eq!(missing.len(), EXPECTED_SECURITY_HEADERS.len());
        for expected in EXPECTED_SECURITY_HEADERS {
            assert!(
                missing.iter().any(|s| s.detail == *expected),
                "expected a missing-header signal for {expected}"
            );
        }
    }

    #[test]
    fn present_security_header_is_not_flagged_case_insensitively() {
        let headers = vec![
            ("x-frame-options".to_string(), "DENY".to_string()),
            ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
            (
                "strict-transport-security".to_string(),
                "max-age=31536000".to_string(),
            ),
            (
                "content-security-policy".to_string(),
                "default-src 'self'".to_string(),
            ),
        ];
        let signals = analyze(&response(headers, "ok"));
        assert!(
            !signals
                .iter()
                .any(|s| s.kind == SignalKind::MissingSecurityHeader),
            "no missing-header signals expected: {signals:?}"
        );
    }

    // --- Task 3.4 / 5.2: error-detail leakage in the body -------------------

    #[test]
    fn flags_stack_trace_body() {
        let body = "Traceback (most recent call last):\n  File ...\nException: boom";
        let signals = analyze(&response(hardened_headers(), body));
        assert!(signals
            .iter()
            .any(|s| s.kind == SignalKind::ErrorDetailLeakage));
    }

    // --- Task 3.5 / 5.2: clean response yields no signals -------------------

    #[test]
    fn clean_response_yields_no_signals() {
        let body = r#"{"status":"ok","items":[]}"#;
        let signals = analyze(&response(hardened_headers(), body));
        assert!(
            signals.is_empty(),
            "a hardened, banner-free, clean-body response should raise nothing: {:?}",
            kinds(&signals)
        );
    }
}
