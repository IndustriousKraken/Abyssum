//! Per-scan options: the choices carried with one scan run.
//!
//! A [`ScanOptions`] is a small, open bag of per-scan choices — whether a scan
//! runs active subdomain brute-force, which timing profile shapes its pacing,
//! which custom wordlist it uses. Those concrete options arrive with later feature
//! changes (`g05`/`g06`/`g07`); this is the shared mechanism that carries them on
//! the scan and exposes them to scanners at run time, so a scan-specific choice has
//! somewhere to live instead of coming only from global config.
//!
//! It is deliberately **data only** — a named set of values, nothing more. Options
//! never carry a request path, so exposing them to scanners cannot introduce a way
//! around the pacing floor: every request still goes through
//! [`ScanContext::send`](crate::scan::ScanContext::send).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The per-scan choices carried with one scan. An empty set means "no options":
/// every default applies and the scan behaves exactly as one started before
/// per-scan options existed.
///
/// Options are named string values so the set is **open to extension** — a later
/// feature records its choice under its own key and reads it back through the scan
/// context, without this type changing shape. Values are strings because the
/// carried choices are simple scalars (a flag, a profile name, a wordlist id); the
/// consuming feature parses its own value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScanOptions {
    values: BTreeMap<String, String>,
}

impl ScanOptions {
    /// An empty option set — defaults apply.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set option `key` to `value` (builder-style), replacing any prior value.
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.set(key, value);
        self
    }

    /// Record option `key` = `value`, replacing any prior value.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.values.insert(key.into(), value.into());
    }

    /// Read option `key`, or `None` if it is unset (the consumer then applies its
    /// default).
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    /// Whether no option is set (defaults apply).
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_by_default_reads_none() {
        let opts = ScanOptions::new();
        assert!(opts.is_empty());
        assert_eq!(opts.get("anything"), None);
    }

    #[test]
    fn set_and_read_back_a_value() {
        let opts = ScanOptions::new().with("timing_profile", "organic");
        assert!(!opts.is_empty());
        assert_eq!(opts.get("timing_profile"), Some("organic"));
        assert_eq!(opts.get("absent"), None);
    }

    #[test]
    fn last_write_wins() {
        let mut opts = ScanOptions::new();
        opts.set("k", "one");
        opts.set("k", "two");
        assert_eq!(opts.get("k"), Some("two"));
    }

    #[test]
    fn serde_round_trips_as_a_plain_map() {
        let opts = ScanOptions::new().with("a", "1");
        let json = serde_json::to_string(&opts).unwrap();
        assert_eq!(json, r#"{"a":"1"}"#); // transparent: no wrapper field
        let back: ScanOptions = serde_json::from_str(&json).unwrap();
        assert_eq!(back, opts);
    }
}
