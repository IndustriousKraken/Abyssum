//! Bundled reference-data assets, embedded into the binary at build time.
//!
//! The curated wordlists and the User-Agent pool ship as files under
//! `assets/seed/`, embedded here with [`include_str!`]. Embedding keeps Abyssum a
//! single self-contained binary (canon) while still letting the data live in the
//! database once seeded: the file is the *source*, the database row is the
//! runtime copy (queryable, extensible).
//!
//! Each wordlist file seeds exactly one **named list**; a scanner loads one or
//! more lists *by name* (see the change's design table), which is why lookup is
//! keyed by list name rather than by scanner id.

use serde::Deserialize;

/// A bundled wordlist asset: the list name it seeds, its embedded text, and
/// whether each line is a `label|body` pair (labeled) or a plain value.
pub struct WordlistAsset {
    /// The name the list is seeded and looked up under.
    pub name: &'static str,
    /// The raw embedded file contents.
    pub raw: &'static str,
    /// Whether each entry is `label|body` (split on the first `|`) rather than a
    /// plain value.
    pub labeled: bool,
}

/// Every bundled wordlist, in the order it is seeded. Each file seeds exactly one
/// named list. `subdomains` belongs to no scanner (a target helper); `cors` and
/// `idor` seed no list (they craft their candidates inline).
pub static WORDLISTS: &[WordlistAsset] = &[
    WordlistAsset {
        name: "rest_endpoints",
        raw: include_str!("../../../assets/seed/wordlists/endpoints.txt"),
        labeled: false,
    },
    WordlistAsset {
        name: "rest_api_bases",
        raw: include_str!("../../../assets/seed/wordlists/api_bases.txt"),
        labeled: false,
    },
    WordlistAsset {
        name: "openapi_paths",
        raw: include_str!("../../../assets/seed/wordlists/openapi_paths.txt"),
        labeled: false,
    },
    WordlistAsset {
        name: "bac_paths",
        raw: include_str!("../../../assets/seed/wordlists/paths.txt"),
        labeled: false,
    },
    WordlistAsset {
        name: "bac_paths_short",
        raw: include_str!("../../../assets/seed/wordlists/paths_short.txt"),
        labeled: false,
    },
    WordlistAsset {
        name: "graphql_paths",
        raw: include_str!("../../../assets/seed/wordlists/paths_graphql.txt"),
        labeled: false,
    },
    WordlistAsset {
        name: "graphql_queries",
        raw: include_str!("../../../assets/seed/wordlists/graphql_queries.txt"),
        labeled: true,
    },
    WordlistAsset {
        name: "subdomains",
        raw: include_str!("../../../assets/seed/wordlists/subdomains.txt"),
        labeled: false,
    },
];

/// The embedded User-Agent pool, as raw JSON.
pub static USER_AGENTS_JSON: &str = include_str!("../../../assets/seed/user-agents.json");

/// One parsed wordlist entry: a value, plus an optional label for labeled lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedEntry {
    /// The candidate path / query body.
    pub value: String,
    /// The entry's label (e.g. a named GraphQL query), or `None` for plain lists.
    pub label: Option<String>,
}

/// Parse a wordlist asset into its ordered entries.
///
/// Blank lines and `#` comment lines are skipped; remaining lines are trimmed.
/// A labeled list splits on the **first** `|` into `(label, value)`; a labeled
/// line with no `|` falls back to a plain value with no label.
pub fn parse_wordlist(asset: &WordlistAsset) -> Vec<ParsedEntry> {
    asset
        .raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            if asset.labeled {
                if let Some((label, body)) = line.split_once('|') {
                    return ParsedEntry {
                        value: body.trim().to_string(),
                        label: Some(label.trim().to_string()),
                    };
                }
            }
            ParsedEntry {
                value: line.to_string(),
                label: None,
            }
        })
        .collect()
}

/// A User-Agent parsed from the bundled pool: its display name, category, the
/// literal header value, and whether it is realistic (browser/mobile) traffic.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SeedUserAgent {
    /// Human-facing label (e.g. "Chrome (Windows)"). Not persisted; for the pool
    /// JSON only.
    pub name: String,
    /// Coarse category: browser, mobile, bot, security.
    pub category: String,
    /// The literal `User-Agent` header value.
    pub value: String,
    /// Whether this identity is part of the default (stealth) rotation pool.
    pub realistic: bool,
}

/// Deserialization shape of `user-agents.json`. The file's `_comment` key is
/// ignored (no `deny_unknown_fields`).
#[derive(Debug, Deserialize)]
struct UserAgentsFile {
    user_agents: Vec<SeedUserAgent>,
}

/// Parse the bundled User-Agent pool into structured entries.
///
/// The asset is compiled into the binary, so malformed JSON is a build-time
/// invariant rather than a runtime condition — a parse failure here means the
/// shipped asset is broken, and panicking surfaces that immediately.
pub fn parse_user_agents() -> Vec<SeedUserAgent> {
    let file: UserAgentsFile = serde_json::from_str(USER_AGENTS_JSON)
        .expect("bundled assets/seed/user-agents.json must be valid JSON");
    file.user_agents
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_wordlist_parses_to_non_empty_trimmed_entries() {
        for asset in WORDLISTS {
            let entries = parse_wordlist(asset);
            assert!(!entries.is_empty(), "{} parsed to nothing", asset.name);
            for entry in &entries {
                assert_eq!(entry.value, entry.value.trim(), "untrimmed value");
                assert!(!entry.value.is_empty(), "blank value survived filtering");
                assert!(!entry.value.starts_with('#'), "comment survived filtering");
            }
        }
    }

    #[test]
    fn labeled_lists_split_on_first_pipe() {
        let asset = WORDLISTS
            .iter()
            .find(|a| a.name == "graphql_queries")
            .expect("graphql_queries is bundled");
        let entries = parse_wordlist(asset);
        for entry in &entries {
            assert!(entry.label.is_some(), "labeled entry missing its label");
            assert!(!entry.value.is_empty(), "labeled entry missing its body");
            // The body must not retain the label/pipe separator.
            assert!(entry.label.as_deref() != Some(""), "empty label");
        }
        // A known curated query is present with its label preserved.
        assert!(entries
            .iter()
            .any(|e| e.label.as_deref() == Some("Introspection Query")
                && e.value.contains("__schema")));
    }

    #[test]
    fn plain_lists_have_no_labels() {
        let asset = WORDLISTS
            .iter()
            .find(|a| a.name == "bac_paths")
            .expect("bac_paths is bundled");
        assert!(parse_wordlist(asset).iter().all(|e| e.label.is_none()));
    }

    #[test]
    fn user_agents_parse_with_both_classes() {
        let uas = parse_user_agents();
        assert!(!uas.is_empty());
        assert!(uas.iter().any(|u| u.realistic), "no realistic UA");
        assert!(uas.iter().any(|u| !u.realistic), "no opt-in-only UA");
        // Spot-check a realistic browser identity and a scanner-announcing one.
        assert!(uas
            .iter()
            .any(|u| u.realistic && u.value.contains("Chrome")));
        assert!(uas
            .iter()
            .any(|u| !u.realistic && u.value.contains("Abyssum")));
    }
}
