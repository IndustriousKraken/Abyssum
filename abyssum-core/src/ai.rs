//! Outbound, OpenAI-compatible AI-assist for finding triage.
//!
//! [`analyze_finding`] is the one entry point: given the AI provider [`AiConfig`]
//! and a stored [`Finding`], it assembles a chat-completions request from the
//! finding's persisted fields, POSTs it to the configured endpoint, and returns the
//! model's textual analysis.
//!
//! The capability is **outbound only** — this module only ever *calls out*; it
//! exposes no listener or callback an external agent could use to drive Abyssum.
//! Every call is **best-effort**: a disabled/unconfigured provider, a transport
//! failure, a non-2xx status, a malformed body, or a timeout all map to a clear,
//! non-fatal [`Error::Ai`]. None of them panics or unwinds into the scan engine or
//! the persistence layer — the caller treats the `Err` as a displayable notice.
//!
//! The API key is **optional**: when no key is configured, the request carries *no*
//! `Authorization` header (not an empty bearer token, which some servers reject), so
//! a keyless self-hosted endpoint such as Ollama works as a first-class case.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::AiConfig;
use crate::error::{Error, Result};
use crate::scan::Finding;

/// Default evidence character budget, used when a caller has nothing better.
pub const DEFAULT_MAX_EVIDENCE_CHARS: usize = 4000;

/// The fixed system message. It frames the model as a security analyst assisting
/// **authorized** testing — the phrasing that most affects whether a hosted model
/// will engage with a legitimate analysis request (the keyless/self-hosted path is
/// the other mitigation). This framing is a behavioral requirement, not just copy.
const SYSTEM_PROMPT: &str = "You are a security analyst assisting with authorized \
    bug-bounty and penetration-testing work. The finding below was produced by an \
    automated scan during an authorized security assessment that the operator is \
    permitted to perform. Assess whether the finding is a genuine weakness, judge its \
    severity, explain the security impact, and suggest concrete remediation. Ground \
    your analysis strictly in the evidence provided; do not invent details.";

/// Analyze one stored finding with the configured AI provider, returning the
/// model's analysis text.
///
/// Best-effort and total: every failure mode is an [`Error::Ai`] carrying a clear
/// message. This function never panics and never returns an error that should abort
/// the caller — callers render the `Err` as a notice in place of an analysis.
pub async fn analyze_finding(config: &AiConfig, finding: &Finding) -> Result<String> {
    if !config.enabled {
        return Err(Error::Ai("AI assistance is disabled".to_string()));
    }
    let base = config.base_url.trim().trim_end_matches('/');
    if base.is_empty() || config.model.trim().is_empty() {
        return Err(Error::Ai(
            "AI assistance is not configured (set ai.base_url and ai.model)".to_string(),
        ));
    }

    let request = ChatRequest::build(config, finding);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.timeout_seconds))
        .build()
        .map_err(|e| Error::Ai(format!("could not build the AI HTTP client: {e}")))?;

    let url = format!("{base}/chat/completions");
    let mut builder = client.post(&url).json(&request);
    // Attach a bearer credential ONLY when a non-empty key is configured. A blank
    // key is treated as absent: no authorization header is sent at all.
    if let Some(key) = effective_key(config) {
        builder = builder.bearer_auth(key);
    }

    let response = builder.send().await.map_err(|e| {
        if e.is_timeout() {
            Error::Ai(format!(
                "the AI request timed out after {}s",
                config.timeout_seconds
            ))
        } else {
            Error::Ai(format!("could not reach the AI provider: {e}"))
        }
    })?;

    let status = response.status();
    if !status.is_success() {
        return Err(Error::Ai(format!(
            "the AI provider returned an error status ({})",
            status.as_u16()
        )));
    }

    let body = response
        .text()
        .await
        .map_err(|e| Error::Ai(format!("could not read the AI provider's response: {e}")))?;
    parse_analysis(&body)
}

/// The configured key with surrounding whitespace stripped, or `None` when it is
/// absent or blank. A blank key must behave exactly like no key.
fn effective_key(config: &AiConfig) -> Option<&str> {
    config
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
}

/// One chat message (role + content) in the OpenAI-compatible shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Message {
    role: String,
    content: String,
}

/// The non-streaming chat-completions request body.
#[derive(Debug, Clone, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<Message>,
    /// Always `false`: the analysis is shown as one block, which keeps response
    /// handling simple and the best-effort error mapping total.
    stream: bool,
    temperature: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u32>,
}

impl ChatRequest {
    /// Assemble the request from the provider config and the finding.
    fn build(config: &AiConfig, finding: &Finding) -> Self {
        Self {
            model: config.model.trim().to_string(),
            messages: build_messages(config.max_evidence_chars, finding),
            stream: false,
            temperature: config.temperature,
            max_tokens: config.max_tokens,
        }
    }
}

/// Build the two messages: a fixed authorized-context system message, and a user
/// message carrying the finding's scanner id, target, status, severity, title, and
/// (truncated) evidence. Pure and deterministic, so prompt assembly is unit-tested
/// without any network.
fn build_messages(max_evidence_chars: usize, finding: &Finding) -> Vec<Message> {
    let (evidence, truncated) = render_evidence(finding, max_evidence_chars);
    let evidence_label = if truncated {
        "Evidence (truncated):"
    } else {
        "Evidence:"
    };
    let user = format!(
        "Scanner: {scanner}\n\
         Target: {target}\n\
         Status: {status}\n\
         Severity: {severity}\n\
         Title: {title}\n\n\
         {evidence_label}\n{evidence}",
        scanner = finding.scanner_id,
        target = finding.target.full_url(),
        status = label(&finding.status),
        severity = label(&finding.severity),
        title = finding.title,
    );
    vec![
        Message {
            role: "system".to_string(),
            content: SYSTEM_PROMPT.to_string(),
        },
        Message {
            role: "user".to_string(),
            content: user,
        },
    ]
}

/// Render the finding's evidence to text, truncated to `max_chars`. Returns the
/// text and whether it was truncated (so the prompt can mark it). Absent evidence
/// renders a neutral placeholder so the request still completes.
fn render_evidence(finding: &Finding, max_chars: usize) -> (String, bool) {
    let text = match &finding.evidence {
        Some(value) => serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()),
        None => return ("(no structured evidence was captured)".to_string(), false),
    };
    truncate_chars(text, max_chars)
}

/// Truncate `text` to at most `max_chars` characters (not bytes, so multi-byte
/// chars are never split), reporting whether it was shortened.
fn truncate_chars(text: String, max_chars: usize) -> (String, bool) {
    if text.chars().count() <= max_chars {
        return (text, false);
    }
    let truncated: String = text.chars().take(max_chars).collect();
    (truncated, true)
}

/// The lowercase label for a serde-`Serialize` enum (`Severity`/`Status`), reusing
/// their lowercase serde renames rather than duplicating a match here.
fn label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// The relevant slice of a chat-completions response.
#[derive(Debug, Deserialize)]
struct ChatResponse {
    #[serde(default)]
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Debug, Deserialize)]
struct ResponseMessage {
    #[serde(default)]
    content: Option<String>,
}

/// Parse the assistant text from `choices[0].message.content`. A body that is not
/// valid JSON, has missing/empty `choices`, or carries a null/absent/blank
/// `content` is a malformed response → a clear non-fatal error, never a panic.
fn parse_analysis(body: &str) -> Result<String> {
    let parsed: ChatResponse = serde_json::from_str(body).map_err(|_| {
        Error::Ai("the AI provider returned a response that could not be interpreted".to_string())
    })?;
    let content = parsed
        .choices
        .into_iter()
        .next()
        .and_then(|choice| choice.message.content)
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty());
    content.ok_or_else(|| Error::Ai("the AI provider returned no analysis text".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{Finding, Severity, Status, Target};

    fn finding_with_evidence(evidence: serde_json::Value) -> Finding {
        Finding::builder(
            "cors",
            Target::parse("https://api.example.com")
                .unwrap()
                .with_path("/data"),
            "Permissive CORS reflects arbitrary Origin",
        )
        .severity(Severity::High)
        .status(Status::Vulnerable)
        .evidence(evidence)
        .build()
    }

    #[test]
    fn prompt_carries_authorized_framing_and_all_finding_fields() {
        let finding = finding_with_evidence(serde_json::json!({ "origin": "https://evil.test" }));
        let messages = build_messages(4000, &finding);

        assert_eq!(messages.len(), 2);
        // System message frames the work as authorized analysis.
        assert_eq!(messages[0].role, "system");
        let sys = messages[0].content.to_lowercase();
        assert!(sys.contains("authorized"));
        assert!(sys.contains("security analyst"));

        // The user message carries scanner id, target, status, severity, title, and
        // evidence — each in its own labelled line.
        assert_eq!(messages[1].role, "user");
        let user = &messages[1].content;
        assert!(user.contains("Scanner: cors"));
        assert!(user.contains("Target: https://api.example.com/data"));
        assert!(user.contains("Status: vulnerable"));
        assert!(user.contains("Severity: high"));
        assert!(user.contains("Title: Permissive CORS reflects arbitrary Origin"));
        assert!(user.contains("https://evil.test"));
        // Untruncated evidence is not marked as truncated.
        assert!(user.contains("Evidence:"));
        assert!(!user.contains("(truncated)"));
    }

    #[test]
    fn oversized_evidence_is_truncated_and_marked() {
        // Evidence far larger than the bound.
        let big = "A".repeat(10_000);
        let finding = finding_with_evidence(serde_json::json!({ "blob": big }));
        let messages = build_messages(100, &finding);
        let user = &messages[1].content;

        assert!(user.contains("Evidence (truncated):"));
        // The rendered evidence portion is bounded near the limit (plus the small
        // fixed header lines), nowhere near the 10k original.
        assert!(
            user.len() < 1000,
            "evidence should be truncated: {} chars",
            user.len()
        );
    }

    #[test]
    fn absent_evidence_still_builds_a_request() {
        let finding = Finding::builder(
            "rest_discovery",
            Target::parse("https://example.com").unwrap(),
            "Endpoint reachable",
        )
        .build();
        let messages = build_messages(4000, &finding);
        assert!(messages[1].content.contains("no structured evidence"));
    }

    #[test]
    fn parse_extracts_assistant_text() {
        let body =
            r#"{"choices":[{"message":{"role":"assistant","content":"  This is real.  "}}]}"#;
        assert_eq!(parse_analysis(body).unwrap(), "This is real.");
    }

    #[test]
    fn parse_rejects_empty_choices() {
        let body = r#"{"choices":[]}"#;
        let err = parse_analysis(body).unwrap_err();
        assert!(matches!(err, Error::Ai(_)), "got {err:?}");
    }

    #[test]
    fn parse_rejects_missing_choices() {
        let body = r#"{"id":"x","object":"chat.completion"}"#;
        assert!(matches!(parse_analysis(body).unwrap_err(), Error::Ai(_)));
    }

    #[test]
    fn parse_rejects_null_content() {
        let body = r#"{"choices":[{"message":{"role":"assistant","content":null}}]}"#;
        assert!(matches!(parse_analysis(body).unwrap_err(), Error::Ai(_)));
    }

    #[test]
    fn parse_rejects_non_json_body() {
        assert!(matches!(
            parse_analysis("not json at all").unwrap_err(),
            Error::Ai(_)
        ));
    }

    #[test]
    fn effective_key_treats_blank_as_absent() {
        let mut cfg = AiConfig::default();
        assert!(effective_key(&cfg).is_none());
        cfg.api_key = Some("   ".to_string());
        assert!(effective_key(&cfg).is_none());
        cfg.api_key = Some(" sk-abc ".to_string());
        assert_eq!(effective_key(&cfg), Some("sk-abc"));
    }

    #[tokio::test]
    async fn disabled_returns_notice_without_calling_out() {
        let cfg = AiConfig {
            enabled: false,
            ..AiConfig::default()
        };
        let finding = finding_with_evidence(serde_json::json!({ "x": 1 }));
        let err = analyze_finding(&cfg, &finding).await.unwrap_err();
        assert!(matches!(err, Error::Ai(_)), "got {err:?}");
        assert!(err.to_string().to_lowercase().contains("disabled"));
    }

    #[tokio::test]
    async fn unconfigured_returns_notice() {
        let cfg = AiConfig {
            base_url: "   ".to_string(),
            ..AiConfig::default()
        };
        let finding = finding_with_evidence(serde_json::json!({ "x": 1 }));
        let err = analyze_finding(&cfg, &finding).await.unwrap_err();
        assert!(err.to_string().to_lowercase().contains("not configured"));
    }
}
