//! The bundled reference-data assets, embedded into the binary at build time.
//!
//! The curated wordlists (`assets/seed/wordlists/*.txt`) and the User-Agent pool
//! (`assets/seed/user-agents.json`) are compiled in with [`include_str!`], so the
//! data ships inside the single self-contained binary (canon) yet still lands in
//! the database on first run — queryable and extensible at runtime.
//!
//! This module owns the *one* canonical parse of each asset. The seeder and the
//! tests both go through [`bundled_wordlist`] / [`bundled_user_agents`], so the
//! "bundled asset count" a test asserts is exactly what the seeder inserts: blank
//! lines and `#` comments are dropped, surrounding whitespace is trimmed, and a
//! value that repeats within a list collapses to its first occurrence (mirroring
//! the `UNIQUE(list_name, value)` constraint).

use serde::Deserialize;

use crate::error::{Error, Result};

/// One entry of a named wordlist as parsed from its bundled asset: the candidate
/// `value` (a path or query body) and an optional `label` (e.g. a GraphQL query
/// name). Plain lists carry no label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WordlistEntry {
    /// The candidate path / query body probed against the target.
    pub value: String,
    /// A human label for the entry, present only for labelled lists.
    pub label: Option<String>,
}

/// A bundled wordlist asset: the embedded file content, the list name it seeds,
/// and whether its lines carry a `label|body` prefix to split.
struct WordlistAsset {
    /// The list name this asset seeds (the key a scanner looks up).
    name: &'static str,
    /// The raw embedded file content.
    content: &'static str,
    /// `true` when each line is `label|body` (split on the first `|`).
    labelled: bool,
}

/// The bundled wordlists, one asset per file. The list name — not the file name —
/// is the lookup key, because one scanner draws on several lists (see the design
/// table). `graphql_queries` is the only labelled list: its lines are
/// `name|query-body`.
const WORDLIST_ASSETS: &[WordlistAsset] = &[
    WordlistAsset {
        name: "rest_endpoints",
        content: include_str!("../../../assets/seed/wordlists/endpoints.txt"),
        labelled: false,
    },
    WordlistAsset {
        name: "rest_api_bases",
        content: include_str!("../../../assets/seed/wordlists/api_bases.txt"),
        labelled: false,
    },
    WordlistAsset {
        name: "openapi_paths",
        content: include_str!("../../../assets/seed/wordlists/openapi_paths.txt"),
        labelled: false,
    },
    WordlistAsset {
        name: "bac_paths",
        content: include_str!("../../../assets/seed/wordlists/paths.txt"),
        labelled: false,
    },
    WordlistAsset {
        name: "bac_paths_short",
        content: include_str!("../../../assets/seed/wordlists/paths_short.txt"),
        labelled: false,
    },
    WordlistAsset {
        name: "graphql_paths",
        content: include_str!("../../../assets/seed/wordlists/paths_graphql.txt"),
        labelled: false,
    },
    WordlistAsset {
        name: "graphql_queries",
        content: include_str!("../../../assets/seed/wordlists/graphql_queries.txt"),
        labelled: true,
    },
    WordlistAsset {
        name: "subdomains",
        content: include_str!("../../../assets/seed/wordlists/subdomains.txt"),
        labelled: false,
    },
];

/// The embedded User-Agent pool.
const USER_AGENTS_JSON: &str = include_str!("../../../assets/seed/user-agents.json");

/// A User-Agent as parsed from `user-agents.json`. `realistic` entries form the
/// default stealth rotation pool; the rest exist only for explicit opt-in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SeedUserAgent {
    /// Human-friendly name, e.g. "Chrome (Windows)".
    pub name: String,
    /// Coarse category, e.g. `browser`, `mobile`, `bot`, `security`.
    pub category: String,
    /// Whether the entry looks like ordinary browser/mobile traffic. Only these
    /// are used by default; non-realistic entries trip basic IDS/IPS signatures.
    pub realistic: bool,
    /// The literal `User-Agent` header value.
    pub value: String,
}

/// The shape of `user-agents.json`: a wrapper object around the pool array. The
/// leading `_comment` field is ignored.
#[derive(Deserialize)]
struct UserAgentsFile {
    user_agents: Vec<SeedUserAgent>,
}

/// The names of every bundled wordlist, in seeded order.
pub fn wordlist_names() -> impl Iterator<Item = &'static str> {
    WORDLIST_ASSETS.iter().map(|asset| asset.name)
}

/// The parsed entries of the bundled wordlist `name`, in seeded order, or an
/// empty vector if no asset bears that name. This is the single source the seeder
/// inserts from, so a list's bundled count equals its row count after seeding.
pub fn bundled_wordlist(name: &str) -> Vec<WordlistEntry> {
    WORDLIST_ASSETS
        .iter()
        .find(|asset| asset.name == name)
        .map(parse_wordlist)
        .unwrap_or_default()
}

/// Parse a wordlist asset into ordered entries: trim each line, drop blanks and
/// `#` comments, split `label|body` for labelled lists, and collapse a value that
/// repeats within the list to its first occurrence.
fn parse_wordlist(asset: &WordlistAsset) -> Vec<WordlistEntry> {
    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::new();
    for raw in asset.content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let entry = if asset.labelled {
            match line.split_once('|') {
                Some((label, body)) => WordlistEntry {
                    value: body.trim().to_string(),
                    label: Some(label.trim().to_string()),
                },
                // A labelled list line without a separator degrades to a plain
                // value rather than being dropped.
                None => WordlistEntry {
                    value: line.to_string(),
                    label: None,
                },
            }
        } else {
            WordlistEntry {
                value: line.to_string(),
                label: None,
            }
        };
        if seen.insert(entry.value.clone()) {
            entries.push(entry);
        }
    }
    entries
}

/// Parse the embedded `user-agents.json` into structured entries. Returns
/// [`Error::Seed`] if the embedded JSON is malformed (a build-time bug).
pub fn bundled_user_agents() -> Result<Vec<SeedUserAgent>> {
    let file: UserAgentsFile = serde_json::from_str(USER_AGENTS_JSON)
        .map_err(|e| Error::Seed(format!("failed to parse bundled user-agents.json: {e}")))?;
    Ok(file.user_agents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_and_blanks_are_stripped() {
        // `endpoints.txt` is heavily commented; no parsed value may be a comment
        // or blank.
        let entries = bundled_wordlist("rest_endpoints");
        assert!(!entries.is_empty());
        for entry in &entries {
            assert!(!entry.value.is_empty());
            assert!(!entry.value.starts_with('#'), "comment leaked: {entry:?}");
            assert!(entry.label.is_none(), "plain list carries no label");
        }
        // A representative real value survives.
        assert!(entries.iter().any(|e| e.value == "health"));
    }

    #[test]
    fn graphql_queries_split_label_and_body() {
        let entries = bundled_wordlist("graphql_queries");
        assert!(!entries.is_empty());
        for entry in &entries {
            let label = entry.label.as_deref().unwrap_or_default();
            assert!(!label.is_empty(), "labelled entry needs a label: {entry:?}");
            assert!(!entry.value.is_empty(), "labelled entry needs a body");
            // The separator must have been consumed, not carried into either side.
            assert!(!entry.value.contains('|') || entry.value.starts_with("query"));
        }
        // The first line splits as documented.
        let first = &entries[0];
        assert_eq!(first.label.as_deref(), Some("Introspection Query"));
        assert!(first.value.starts_with("query IntrospectionQuery"));
    }

    #[test]
    fn every_named_list_is_non_empty_and_unique() {
        for name in wordlist_names() {
            let entries = bundled_wordlist(name);
            assert!(!entries.is_empty(), "{name} parsed empty");
            let mut values: Vec<_> = entries.iter().map(|e| &e.value).collect();
            let total = values.len();
            values.sort();
            values.dedup();
            assert_eq!(
                total,
                values.len(),
                "{name} has duplicate values after parse"
            );
        }
    }

    #[test]
    fn unknown_list_parses_to_empty() {
        assert!(bundled_wordlist("does_not_exist").is_empty());
    }

    #[test]
    fn user_agents_parse_with_a_realistic_subset() {
        let agents = bundled_user_agents().unwrap();
        assert!(!agents.is_empty());
        // Both subsets are present in the curated pool.
        assert!(agents.iter().any(|a| a.realistic));
        assert!(agents.iter().any(|a| !a.realistic));
        // Every field is populated.
        for agent in &agents {
            assert!(!agent.name.is_empty());
            assert!(!agent.category.is_empty());
            assert!(!agent.value.is_empty());
        }
        // The scanner-announcing identity is present but flagged non-realistic.
        let abyssum = agents
            .iter()
            .find(|a| a.value.starts_with("Abyssum/"))
            .expect("the Abyssum identity is in the pool");
        assert!(
            !abyssum.realistic,
            "the scanner identity must not be realistic"
        );
    }
}
