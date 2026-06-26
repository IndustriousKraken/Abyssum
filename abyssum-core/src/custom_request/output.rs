//! Rendering a [`RequestOutcome`] to the two operator-selected forms.
//!
//! Both forms describe the same outcome — the echoed request, the captured
//! response (or the error), and the advisory signals — and both cap the response
//! body preview at [`body_preview_cap`](RequestOutcome::body_preview_cap) so
//! neither carries an unbounded payload. The JSON form is a single
//! machine-parseable document; the human form is readable text.

use std::fmt::Write as _;
use std::str::FromStr;

use serde_json::{json, Value};

use super::response::{CaptureResult, RequestOutcome};

/// The operator-selected output form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OutputFormat {
    /// Readable text (the `--output pretty` form).
    #[default]
    Human,
    /// A single structured JSON document (the `--output json` form).
    Json,
}

impl FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "pretty" | "human" | "text" => Ok(OutputFormat::Human),
            "json" => Ok(OutputFormat::Json),
            other => Err(format!(
                "unknown output format {other:?} (expected pretty|json)"
            )),
        }
    }
}

impl RequestOutcome {
    /// Render this outcome in the selected form.
    pub fn render(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Human => self.render_human(),
            OutputFormat::Json => self.render_json(),
        }
    }

    /// Render the readable text form: request line, status, timing, final URL and
    /// redirect hop count, response headers, the (capped) body preview, and the
    /// signals.
    fn render_human(&self) -> String {
        let mut out = String::new();

        out.push_str("=== Request ===\n");
        let _ = writeln!(out, "{} {}", self.request.method, self.request.url);
        for (name, value) in &self.request.headers {
            let _ = writeln!(out, "{name}: {value}");
        }
        if let Some(body) = &self.request.body {
            let _ = writeln!(out, "\n{body}");
        }

        match &self.result {
            CaptureResult::Error(err) => {
                out.push_str("\n=== Error ===\n");
                let _ = writeln!(out, "{err}");
            }
            CaptureResult::Response(resp) => {
                out.push_str("\n=== Response ===\n");
                let _ = writeln!(out, "Status: {}", resp.status);
                let _ = writeln!(out, "Time: {} ms", resp.elapsed.as_millis());
                let _ = writeln!(
                    out,
                    "Final URL: {} ({} redirect{} followed)",
                    resp.final_url,
                    resp.redirect_count,
                    if resp.redirect_count == 1 { "" } else { "s" }
                );
                for (name, value) in &resp.headers {
                    let _ = writeln!(out, "{name}: {value}");
                }

                let (body, truncated) = resp.display_body(self.body_preview_cap);
                if truncated {
                    let _ = writeln!(
                        out,
                        "\n--- Body (truncated to {} bytes) ---",
                        self.body_preview_cap
                    );
                } else {
                    out.push_str("\n--- Body ---\n");
                }
                out.push_str(&body);
                if !body.ends_with('\n') {
                    out.push('\n');
                }
            }
        }

        let _ = writeln!(out, "\n=== Signals ({}) ===", self.signals.len());
        if self.signals.is_empty() {
            out.push_str("No signals.\n");
        } else {
            for signal in &self.signals {
                let _ = writeln!(out, "[{}] {}", signal.kind.label(), signal.detail);
            }
        }

        out
    }

    /// Render the structured JSON document: the echoed request, the captured
    /// response (or error), and the signals.
    fn render_json(&self) -> String {
        let request = json!({
            "method": self.request.method,
            "url": self.request.url,
            "headers": headers_to_json(&self.request.headers),
            "body": self.request.body,
        });

        let (response, error) = match &self.result {
            CaptureResult::Response(resp) => {
                let (body, truncated) = resp.display_body(self.body_preview_cap);
                let response = json!({
                    "status": resp.status,
                    "final_url": resp.final_url,
                    "redirect_count": resp.redirect_count,
                    "elapsed_ms": resp.elapsed.as_millis() as u64,
                    "content_type": resp.content_type(),
                    "headers": headers_to_json(&resp.headers),
                    "body": body,
                    "body_truncated": truncated,
                });
                (response, Value::Null)
            }
            CaptureResult::Error(err) => (Value::Null, Value::String(err.clone())),
        };

        let document = json!({
            "request": request,
            "response": response,
            "error": error,
            "signals": self.signals,
        });

        // Pretty-print so a JSON response body (itself pretty-printed inside the
        // "body" string) reads cleanly. Serialization of this owned value cannot
        // fail; the fallback keeps the function total regardless.
        serde_json::to_string_pretty(&document).unwrap_or_else(|_| document.to_string())
    }
}

/// Represent a header list as a JSON array of `{name, value}` objects, preserving
/// order and any duplicate names (which a map would collapse).
fn headers_to_json(headers: &[(String, String)]) -> Value {
    Value::Array(
        headers
            .iter()
            .map(|(name, value)| json!({ "name": name, "value": value }))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custom_request::analysis::{Signal, SignalKind};
    use crate::custom_request::response::CapturedResponse;
    use crate::custom_request::spec::PreparedRequest;
    use std::time::Duration;

    fn sample_outcome() -> RequestOutcome {
        RequestOutcome {
            request: PreparedRequest {
                method: "GET".to_string(),
                url: "https://api.test/users".to_string(),
                headers: vec![("Accept".to_string(), "application/json".to_string())],
                body: None,
            },
            result: CaptureResult::Response(CapturedResponse {
                status: 200,
                headers: vec![
                    ("content-type".to_string(), "application/json".to_string()),
                    ("server".to_string(), "nginx".to_string()),
                ],
                body: r#"{"ok":true}"#.to_string(),
                elapsed: Duration::from_millis(42),
                final_url: "https://api.test/users".to_string(),
                redirect_count: 0,
            }),
            signals: vec![Signal {
                kind: SignalKind::InformationDisclosure,
                detail: "server: nginx".to_string(),
            }],
            body_preview_cap: 64 * 1024,
        }
    }

    #[test]
    fn output_format_parses() {
        assert_eq!(
            "pretty".parse::<OutputFormat>().unwrap(),
            OutputFormat::Human
        );
        assert_eq!("JSON".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert!("xml".parse::<OutputFormat>().is_err());
    }

    #[test]
    fn json_form_is_machine_parseable_and_complete() {
        let doc: Value =
            serde_json::from_str(&sample_outcome().render(OutputFormat::Json)).unwrap();
        assert_eq!(doc["request"]["method"], "GET");
        assert_eq!(doc["response"]["status"], 200);
        assert_eq!(doc["error"], Value::Null);
        assert_eq!(doc["signals"].as_array().unwrap().len(), 1);
        assert_eq!(doc["signals"][0]["kind"], "information-disclosure");
    }

    #[test]
    fn json_form_pretty_prints_json_body() {
        let doc: Value =
            serde_json::from_str(&sample_outcome().render(OutputFormat::Json)).unwrap();
        // The body field is the pretty-printed JSON body (a string).
        let body = doc["response"]["body"].as_str().unwrap();
        assert!(
            body.contains('\n'),
            "JSON body should be pretty-printed: {body:?}"
        );
        assert!(body.contains("\"ok\": true"));
    }

    // --- Task 5.5: human and JSON forms describe the same outcome -----------

    #[test]
    fn human_and_json_describe_the_same_outcome() {
        let outcome = sample_outcome();
        let human = outcome.render(OutputFormat::Human);
        let doc: Value = serde_json::from_str(&outcome.render(OutputFormat::Json)).unwrap();

        // Status appears in both.
        assert!(human.contains("Status: 200"));
        assert_eq!(doc["response"]["status"], 200);

        // The request line appears in both.
        assert!(human.contains("GET https://api.test/users"));
        assert_eq!(doc["request"]["url"], "https://api.test/users");

        // Every signal detail appears in the human text, and the counts match.
        let json_signals = doc["signals"].as_array().unwrap();
        assert_eq!(json_signals.len(), outcome.signals.len());
        for signal in &outcome.signals {
            assert!(
                human.contains(&signal.detail),
                "human output missing signal detail {:?}",
                signal.detail
            );
        }
    }

    #[test]
    fn error_outcome_renders_in_both_forms() {
        let mut outcome = sample_outcome();
        outcome.result = CaptureResult::Error("connection refused".to_string());
        outcome.signals.clear();

        let human = outcome.render(OutputFormat::Human);
        assert!(human.contains("=== Error ==="));
        assert!(human.contains("connection refused"));

        let doc: Value = serde_json::from_str(&outcome.render(OutputFormat::Json)).unwrap();
        assert_eq!(doc["error"], "connection refused");
        assert_eq!(doc["response"], Value::Null);
    }
}
