//! The shared scan-target model.
//!
//! One [`Target`] type is used by every scanner, the orchestrator, and
//! persistence so a target is described the same way everywhere. A target names
//! an **origin** (`base_url`: scheme + host + optional port), may carry a `path`
//! beneath that origin, and may carry an `id_template` — a path with an
//! object-reference placeholder (e.g. `/api/users/{id}`) that
//! reference-enumeration (IDOR) scanners substitute concrete values into.
//!
//! The registrable **host** for per-domain pacing is derived from `base_url`, so
//! the rate limiter always keys on the same value the target advertises.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{Error, Result};

/// What a scan points at: an origin, an optional path, and an optional
/// object-reference template.
///
/// Construct with [`Target::new`] / [`Target::parse`]; the origin host (for
/// pacing) and the full URL (for issuing requests) are *derived*, never stored
/// redundantly, so they cannot drift from `base_url`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// The origin: scheme, host, and optional port.
    base_url: Url,
    /// An optional route beneath the origin (e.g. `/api/health`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    /// An optional parameterized path carrying an object-reference placeholder
    /// (e.g. `/api/users/{id}`) for reference-enumeration scanners.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    id_template: Option<String>,
}

impl Target {
    /// Build a target from an already-parsed base URL plus optional `path` and
    /// `id_template`.
    pub fn new(base_url: Url, path: Option<String>, id_template: Option<String>) -> Self {
        Self {
            base_url,
            path,
            id_template,
        }
    }

    /// Build a target from a base-URL string, parsing it. Returns
    /// [`Error::Target`] if the string is not a valid absolute URL.
    pub fn parse(base_url: &str) -> Result<Self> {
        let url = Url::parse(base_url)
            .map_err(|e| Error::Target(format!("invalid base URL {base_url:?}: {e}")))?;
        Ok(Self::new(url, None, None))
    }

    /// Set the path beneath the origin (builder-style).
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Set the object-reference template (builder-style).
    pub fn with_id_template(mut self, template: impl Into<String>) -> Self {
        self.id_template = Some(template.into());
        self
    }

    /// The origin URL identifying the target.
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// The optional path beneath the origin.
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// The optional object-reference template.
    pub fn id_template(&self) -> Option<&str> {
        self.id_template.as_deref()
    }

    /// The registrable host the rate limiter keys on, derived from `base_url`.
    ///
    /// `None` only for the degenerate case of a base URL with no host (e.g. a
    /// `file:` URL); HTTP(S) targets always have one.
    pub fn host(&self) -> Option<&str> {
        self.base_url.host_str()
    }

    /// The full URL to issue a request against: `base_url` joined with `path`
    /// when a path is present, otherwise the base URL itself.
    ///
    /// A path that fails to join (which `url::Url::join` only does for an
    /// unparseable relative reference) falls back to the base URL.
    pub fn full_url(&self) -> Url {
        match &self.path {
            Some(path) => self
                .base_url
                .join(path)
                .unwrap_or_else(|_| self.base_url.clone()),
            None => self.base_url.clone(),
        }
    }

    /// Substitute `value` for the object-reference placeholder in `id_template`
    /// and resolve it against the origin, yielding a concrete full URL.
    ///
    /// Returns `None` when the target carries no template. The placeholder is the
    /// first `{...}` group in the template (the name inside the braces is
    /// ignored, so `{id}`, `{user_id}`, … all work).
    pub fn resolve_id(&self, value: &str) -> Option<Url> {
        let template = self.id_template.as_ref()?;
        let substituted = substitute_placeholder(template, value);
        self.base_url.join(&substituted).ok()
    }
}

/// Replace the first `{...}` placeholder in `template` with `value`. If there is
/// no placeholder the template is returned unchanged.
fn substitute_placeholder(template: &str, value: &str) -> String {
    match (template.find('{'), template.find('}')) {
        (Some(open), Some(close)) if close > open => {
            let mut out = String::with_capacity(template.len() + value.len());
            out.push_str(&template[..open]);
            out.push_str(value);
            out.push_str(&template[close + 1..]);
            out
        }
        _ => template.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_base_url_and_derives_host() {
        let t = Target::parse("https://api.example.com:8443").unwrap();
        assert_eq!(t.host(), Some("api.example.com"));
        assert_eq!(t.base_url().as_str(), "https://api.example.com:8443/");
    }

    #[test]
    fn invalid_base_url_is_a_target_error() {
        let err = Target::parse("not a url").unwrap_err();
        assert!(matches!(err, Error::Target(_)), "got {err:?}");
    }

    #[test]
    fn full_url_joins_path_when_present() {
        let t = Target::parse("https://example.com")
            .unwrap()
            .with_path("/api/users");
        assert_eq!(t.full_url().as_str(), "https://example.com/api/users");
    }

    #[test]
    fn full_url_is_base_when_no_path() {
        let t = Target::parse("https://example.com/root").unwrap();
        assert_eq!(t.full_url().as_str(), "https://example.com/root");
    }

    #[test]
    fn host_keys_pacing_on_the_origin() {
        let t = Target::parse("http://10.0.0.5:3000")
            .unwrap()
            .with_path("/deep/path");
        // Pacing keys on the host regardless of the path.
        assert_eq!(t.host(), Some("10.0.0.5"));
    }

    #[test]
    fn id_template_substitutes_and_resolves() {
        let t = Target::parse("https://example.com")
            .unwrap()
            .with_id_template("/api/users/{id}");
        let url = t.resolve_id("42").unwrap();
        assert_eq!(url.as_str(), "https://example.com/api/users/42");
    }

    #[test]
    fn id_template_ignores_placeholder_name() {
        let t = Target::parse("https://example.com")
            .unwrap()
            .with_id_template("/orders/{order_id}/items");
        let url = t.resolve_id("7").unwrap();
        assert_eq!(url.as_str(), "https://example.com/orders/7/items");
    }

    #[test]
    fn resolve_id_is_none_without_template() {
        let t = Target::parse("https://example.com").unwrap();
        assert!(t.resolve_id("1").is_none());
    }

    #[test]
    fn serde_round_trips() {
        let t = Target::parse("https://example.com")
            .unwrap()
            .with_path("/api")
            .with_id_template("/api/{id}");
        let json = serde_json::to_string(&t).unwrap();
        let back: Target = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }
}
