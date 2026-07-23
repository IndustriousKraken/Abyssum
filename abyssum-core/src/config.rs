//! Layered runtime configuration.
//!
//! Configuration is resolved by layering three sources in strict precedence,
//! where each later source overrides the earlier:
//!
//! 1. **built-in defaults** — conservative by design (see the project's
//!    stealth-and-respect philosophy: non-zero randomized pacing, bounded
//!    concurrency),
//! 2. an optional **YAML file** overlaid on those defaults, and
//! 3. **`ABYSSUM_*` environment variables**, which win.
//!
//! A missing file is not an error — defaults (plus any env overrides) apply. A
//! file that *exists* but is malformed is a hard error: the system fails fast
//! rather than starting in a partially-configured state.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Prefix for all environment-variable configuration overrides.
pub const ENV_PREFIX: &str = "ABYSSUM_";

/// Default configuration-file path: `$XDG_CONFIG_HOME/abyssum/abyssum.yaml`
/// (i.e. `~/.config/abyssum/abyssum.yaml`). This is CWD-independent so a
/// PATH-installed binary reads the same config wherever it is run from. Falls
/// back to the historical CWD-relative `abyssum.yaml` only when no home directory
/// can be resolved. `--config` / `ABYSSUM_CONFIG` still override it.
pub fn default_config_path() -> String {
    config_path_from(&|k| std::env::var(k).ok())
}

/// Default database path: `$XDG_DATA_HOME/abyssum/abyssum.db`
/// (i.e. `~/.local/share/abyssum/abyssum.db`). Because both binaries resolve the
/// database from this one shared default, `abyssum` and `abyssum-web` use the
/// same store with no configuration. Falls back to the historical CWD-relative
/// `data/abyssum.db` only when no home directory can be resolved.
/// `ABYSSUM_DATABASE_PATH` (or a YAML `database.path`) still overrides it.
pub fn default_database_path() -> String {
    database_path_from(&|k| std::env::var(k).ok())
}

/// Resolve an XDG base directory from `var` (e.g. `XDG_CONFIG_HOME`), falling
/// back to `$HOME/`+`home_suffix`. A relative value in `var` is ignored per the
/// XDG spec — honouring it would reintroduce the CWD-relative bug this fixes.
/// Returns `None` when no absolute base can be found (e.g. `HOME` unset), so the
/// caller can choose a sensible relative fallback rather than panic.
fn xdg_base<F>(get_env: &F, var: &str, home_suffix: &str) -> Option<PathBuf>
where
    F: Fn(&str) -> Option<String>,
{
    if let Some(v) = get_env(var) {
        let p = PathBuf::from(&v);
        if p.is_absolute() {
            return Some(p);
        }
    }
    let home = get_env("HOME").filter(|h| !h.is_empty())?;
    Some(PathBuf::from(home).join(home_suffix))
}

/// `default_config_path` with an injectable environment lookup (unit-testable).
fn config_path_from<F>(get_env: &F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    xdg_base(get_env, "XDG_CONFIG_HOME", ".config")
        .map(|d| d.join("abyssum").join("abyssum.yaml"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "abyssum.yaml".to_string())
}

/// `default_database_path` with an injectable environment lookup (unit-testable).
fn database_path_from<F>(get_env: &F) -> String
where
    F: Fn(&str) -> Option<String>,
{
    xdg_base(get_env, "XDG_DATA_HOME", ".local/share")
        .map(|d| d.join("abyssum").join("abyssum.db"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "data/abyssum.db".to_string())
}

/// Top-level runtime configuration for Abyssum.
///
/// Later changes extend this with their own sections (auth secret, AI provider,
/// …) via their own spec deltas; they must not redefine the keys this change
/// owns without a `MODIFIED` requirement.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Web-surface bind settings.
    pub server: ServerConfig,
    /// Where persistent data lives.
    pub database: DatabaseConfig,
    /// Scan pacing and concurrency posture.
    pub scanning: ScanningConfig,
    /// Logging verbosity.
    pub log: LogConfig,
    /// Authentication session lifetimes.
    pub auth: AuthConfig,
    /// Outbound AI-assist provider (see `d02-add-ai-assist`).
    pub ai: AiConfig,
}

/// Web-surface bind settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Host/interface the web surface binds to.
    pub host: String,
    /// TCP port the web surface binds to.
    pub port: u16,
    /// Whether the web custom-requests tool may target private/reserved addresses
    /// (RFC 1918, loopback, link-local, cloud metadata, …). Off by default so a
    /// shared or cloud deployment cannot be used to reach internal infrastructure;
    /// an operator legitimately testing an internal API turns this on deliberately
    /// (conservative-by-default, aggression opt-in).
    pub allow_private_custom_targets: bool,
}

/// Persistence location.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DatabaseConfig {
    /// Filesystem path to the SQLite database. Later persistence work resolves
    /// where to store data from here rather than defining its own setting.
    pub path: String,
}

/// Scan pacing and concurrency.
///
/// Defaults are deliberately conservative: pacing delays are non-zero and form a
/// randomizable window (`min_delay` < `max_delay`), and concurrency is bounded.
/// Aggressive scanning requires the user to deliberately turn these dials up.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanningConfig {
    /// Hard floor on the inter-request delay, in seconds (see rate-limiting,
    /// change a01). Adaptive logic may only ever slow *past* this, never below.
    pub min_delay: f64,
    /// Upper bound of the randomized inter-request delay window, in seconds.
    pub max_delay: f64,
    /// Maximum number of in-flight requests. Finite and modest by default.
    pub max_concurrency: usize,
    /// How often the engine's rotating User-Agent changes. Per-request by default
    /// (every outbound request may present a fresh realistic identity); per-scan
    /// pins one identity for the duration of a scan. See `add-seed-data`.
    pub user_agent_rotation: UserAgentRotation,
    /// Whether the subdomain-recon scanner may perform active DNS brute-force
    /// (join the seeded wordlist onto the apex and test each candidate for
    /// existence). Off by default: reconnaissance stays passive unless the operator
    /// deliberately opts in (conservative-by-default, aggression opt-in).
    pub subdomain_bruteforce: bool,
    /// Upper bound on how many wordlist entries a single scan uses (g07). When a
    /// selected custom wordlist — or the seeded default — holds more than this, the
    /// scan truncates to the bound and reports the truncation rather than dropping
    /// the tail silently, so a 50,000-line paste never quietly becomes a fraction of
    /// itself unnoticed. Applies to the active subdomain brute-force wordlist today.
    pub max_wordlist_entries: usize,
    /// Lower bound of the **support-infrastructure** pacing window, in seconds.
    /// Support lookups — queries to a third-party service the operator uses to
    /// *map* the target (a public DNS resolver, a certificate-transparency / RDAP
    /// aggregator) — are paced by this faster window instead of the target floor,
    /// because those are shared services built for volume, not the target to tread
    /// lightly on. See the rate-limiting capability's support-lane requirement.
    pub support_min_delay: f64,
    /// Upper bound of the support-infrastructure pacing window, in seconds. Kept
    /// small so a large recon phase (e.g. subdomain brute-force over a public
    /// resolver) completes fast, but bounded so it is never abusive toward that
    /// service.
    pub support_max_delay: f64,
    /// Maximum in-flight support-infrastructure lookups, higher than the target
    /// concurrency because a public resolver tolerates more parallelism than a
    /// target's own web server.
    ///
    // ponytail: an unenforced posture knob today, exactly like `max_concurrency`
    // (no engine component reads either yet — scanners issue lookups in a
    // sequential loop); wire both to a shared semaphore if/when lookups are issued
    // concurrently.
    pub support_max_concurrency: usize,
}

/// Granularity of the engine's default User-Agent rotation.
///
/// The default rotation pool is the realistic (browser/mobile) subset of the
/// seeded User-Agent pool; this key governs *how often* the presented identity
/// changes, not *which* pool it is drawn from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UserAgentRotation {
    /// Pick a fresh identity for every outbound request (the default). Maximizes
    /// the blend-in posture across a scan's many requests.
    #[default]
    PerRequest,
    /// Pin one identity for the lifetime of a scan, presenting a single stable
    /// browser identity to the target (more like one ordinary client).
    PerScan,
}

impl std::str::FromStr for UserAgentRotation {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "per-request" | "request" => Ok(Self::PerRequest),
            "per-scan" | "scan" => Ok(Self::PerScan),
            other => Err(format!(
                "expected 'per-request' or 'per-scan', got {other:?}"
            )),
        }
    }
}

/// Authentication session lifetimes.
///
/// A login session is bounded by both an absolute maximum age (a hard ceiling
/// from creation) and an idle timeout (refreshed on each authorized use). The
/// defaults are conservative: a session cannot outlive a day, and an unused one
/// lapses after an hour. See `add-authentication` (c02).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    /// Hard ceiling on a session's age, in hours, regardless of activity.
    pub session_absolute_max_hours: u64,
    /// Idle timeout, in minutes, refreshed on each authorized use.
    pub session_idle_timeout_minutes: u64,
}

/// Outbound AI-assist provider configuration.
///
/// Identifies any OpenAI-compatible chat endpoint by `base_url` + `model`. The
/// `api_key` is **optional**: a keyless self-hosted endpoint (e.g. Ollama) is a
/// first-class, supported case — when no key is configured, requests carry no
/// authorization credential at all. See `d02-add-ai-assist`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AiConfig {
    /// Base URL of the OpenAI-compatible endpoint; `/chat/completions` is appended.
    pub base_url: String,
    /// Model name the endpoint serves.
    pub model: String,
    /// Optional API key. `None`/empty ⇒ no `Authorization` header is sent.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Best-effort per-request timeout, in seconds, so a hung provider cannot stall
    /// triage.
    pub timeout_seconds: u64,
    /// Whether AI assist is enabled. Off ⇒ analyze requests return a clear notice
    /// without any outbound call.
    pub enabled: bool,
    /// Evidence is truncated to this many characters before being sent.
    pub max_evidence_chars: usize,
    /// Sampling temperature; low by default for stable, repeatable analysis.
    pub temperature: f64,
    /// Optional cap on the response length (provider `max_tokens`).
    #[serde(default)]
    pub max_tokens: Option<u32>,
}

/// Logging configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// Verbosity filter, e.g. `info`, `debug`, or a per-target directive such as
    /// `abyssum_core=debug,info` (parsed by `tracing-subscriber`'s `EnvFilter`).
    pub level: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8000,
            allow_private_custom_targets: false,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_database_path(),
        }
    }
}

impl Default for ScanningConfig {
    fn default() -> Self {
        Self {
            min_delay: 1.0,
            max_delay: 3.0,
            max_concurrency: 4,
            user_agent_rotation: UserAgentRotation::default(),
            subdomain_bruteforce: false,
            // A generous default: large enough for a serious recon list, bounded so
            // a huge paste is truncated (visibly) rather than probed in full.
            max_wordlist_entries: 2048,
            // Fast but bounded: ~4–20 lookups/s against a public resolver, versus
            // the 1–3s conservative target floor above.
            support_min_delay: 0.05,
            support_max_delay: 0.25,
            support_max_concurrency: 8,
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            session_absolute_max_hours: 24,
            session_idle_timeout_minutes: 60,
        }
    }
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            base_url: "http://localhost:11434/v1".to_string(),
            model: "llama3.1".to_string(),
            api_key: None,
            timeout_seconds: 30,
            enabled: true,
            max_evidence_chars: 4000,
            temperature: 0.2,
            max_tokens: None,
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}

impl Config {
    /// Load configuration, layering defaults < the YAML file at `path` (if it
    /// exists) < `ABYSSUM_*` process environment variables.
    ///
    /// Returns an [`Error::Config`] if the file exists but is malformed, or if an
    /// environment override holds a value that cannot be parsed.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        Self::load_from(path, |key| std::env::var(key).ok())
    }

    /// Like [`load`](Self::load) but with an injectable environment lookup, so the
    /// precedence logic can be unit-tested without touching the process env.
    pub fn load_from<F>(path: impl AsRef<Path>, get_env: F) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let mut config = Self::from_file_or_default(path)?;
        config.apply_env(get_env)?;
        Ok(config)
    }

    /// Read and parse the YAML file at `path`, overlaying it on the defaults.
    ///
    /// A missing file yields the defaults; a present-but-malformed file is an
    /// [`Error::Config`]. Other I/O failures surface as [`Error::Io`].
    pub fn from_file_or_default(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        match std::fs::read_to_string(path) {
            Ok(contents) => serde_yaml::from_str(&contents)
                .map_err(|e| Error::Config(format!("failed to parse {}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(Error::Io(e)),
        }
    }

    /// Apply `ABYSSUM_*` overrides drawn from `get_env`. Unset variables leave the
    /// existing (default or file) value untouched.
    fn apply_env<F>(&mut self, get_env: F) -> Result<()>
    where
        F: Fn(&str) -> Option<String>,
    {
        if let Some(v) = get_env("ABYSSUM_SERVER_HOST") {
            self.server.host = v;
        }
        if let Some(v) = get_env("ABYSSUM_SERVER_PORT") {
            self.server.port = parse_env("ABYSSUM_SERVER_PORT", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_SERVER_ALLOW_PRIVATE_CUSTOM_TARGETS") {
            self.server.allow_private_custom_targets =
                parse_env("ABYSSUM_SERVER_ALLOW_PRIVATE_CUSTOM_TARGETS", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_DATABASE_PATH") {
            self.database.path = v;
        }
        if let Some(v) = get_env("ABYSSUM_SCANNING_MIN_DELAY") {
            self.scanning.min_delay = parse_env("ABYSSUM_SCANNING_MIN_DELAY", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_SCANNING_MAX_DELAY") {
            self.scanning.max_delay = parse_env("ABYSSUM_SCANNING_MAX_DELAY", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_SCANNING_MAX_CONCURRENCY") {
            self.scanning.max_concurrency = parse_env("ABYSSUM_SCANNING_MAX_CONCURRENCY", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_SCANNING_USER_AGENT_ROTATION") {
            self.scanning.user_agent_rotation =
                parse_env("ABYSSUM_SCANNING_USER_AGENT_ROTATION", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_SCANNING_SUBDOMAIN_BRUTEFORCE") {
            self.scanning.subdomain_bruteforce =
                parse_env("ABYSSUM_SCANNING_SUBDOMAIN_BRUTEFORCE", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_SCANNING_MAX_WORDLIST_ENTRIES") {
            self.scanning.max_wordlist_entries =
                parse_env("ABYSSUM_SCANNING_MAX_WORDLIST_ENTRIES", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_SCANNING_SUPPORT_MIN_DELAY") {
            self.scanning.support_min_delay = parse_env("ABYSSUM_SCANNING_SUPPORT_MIN_DELAY", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_SCANNING_SUPPORT_MAX_DELAY") {
            self.scanning.support_max_delay = parse_env("ABYSSUM_SCANNING_SUPPORT_MAX_DELAY", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_SCANNING_SUPPORT_MAX_CONCURRENCY") {
            self.scanning.support_max_concurrency =
                parse_env("ABYSSUM_SCANNING_SUPPORT_MAX_CONCURRENCY", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_AUTH_SESSION_ABSOLUTE_MAX_HOURS") {
            self.auth.session_absolute_max_hours =
                parse_env("ABYSSUM_AUTH_SESSION_ABSOLUTE_MAX_HOURS", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_AUTH_SESSION_IDLE_TIMEOUT_MINUTES") {
            self.auth.session_idle_timeout_minutes =
                parse_env("ABYSSUM_AUTH_SESSION_IDLE_TIMEOUT_MINUTES", &v)?;
        }
        // AI provider. This section uses the `ABYSSUM_AI__*` (double-underscore)
        // convention so the key need never be written to disk.
        if let Some(v) = get_env("ABYSSUM_AI__BASE_URL") {
            self.ai.base_url = v;
        }
        if let Some(v) = get_env("ABYSSUM_AI__MODEL") {
            self.ai.model = v;
        }
        if let Some(v) = get_env("ABYSSUM_AI__API_KEY") {
            // An empty key from the environment means "no key"; the AI module
            // treats a blank key as absent and sends no authorization header.
            self.ai.api_key = Some(v);
        }
        if let Some(v) = get_env("ABYSSUM_AI__TIMEOUT_SECONDS") {
            self.ai.timeout_seconds = parse_env("ABYSSUM_AI__TIMEOUT_SECONDS", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_AI__ENABLED") {
            self.ai.enabled = parse_env("ABYSSUM_AI__ENABLED", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_AI__MAX_EVIDENCE_CHARS") {
            self.ai.max_evidence_chars = parse_env("ABYSSUM_AI__MAX_EVIDENCE_CHARS", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_AI__TEMPERATURE") {
            self.ai.temperature = parse_env("ABYSSUM_AI__TEMPERATURE", &v)?;
        }
        if let Some(v) = get_env("ABYSSUM_AI__MAX_TOKENS") {
            self.ai.max_tokens = Some(parse_env("ABYSSUM_AI__MAX_TOKENS", &v)?);
        }
        // Log level: `ABYSSUM_LOG` is the documented short form (see design.md);
        // `ABYSSUM_LOG_LEVEL` follows the sectioned naming. `ABYSSUM_LOG` wins.
        if let Some(v) = get_env("ABYSSUM_LOG").or_else(|| get_env("ABYSSUM_LOG_LEVEL")) {
            self.log.level = v;
        }
        Ok(())
    }
}

/// Parse an environment override into the target type, reporting an
/// [`Error::Config`] (not a panic) on bad input.
fn parse_env<T>(key: &str, value: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value
        .trim()
        .parse::<T>()
        .map_err(|e| Error::Config(format!("invalid value for {key}: {value:?} ({e})")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Build an env lookup closure from a list of pairs.
    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key: &str| map.get(key).cloned()
    }

    #[test]
    fn defaults_only_when_no_file_or_env() {
        let cfg = Config::load_from("/nonexistent/abyssum.yaml", |_| None).unwrap();
        assert_eq!(cfg, Config::default());
        assert_eq!(cfg.server.host, "127.0.0.1");
        assert_eq!(cfg.server.port, 8000);
        assert_eq!(cfg.database.path, default_database_path());
        assert_eq!(cfg.log.level, "info");
    }

    #[test]
    fn missing_file_is_not_an_error() {
        let result = Config::from_file_or_default("/definitely/not/here.yaml");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Config::default());
    }

    #[test]
    fn file_overlays_defaults_and_keeps_unset_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abyssum.yaml");
        std::fs::write(&path, "server:\n  port: 9999\n").unwrap();

        let cfg = Config::from_file_or_default(&path).unwrap();
        // overridden key
        assert_eq!(cfg.server.port, 9999);
        // sibling key in the same section keeps its default
        assert_eq!(cfg.server.host, "127.0.0.1");
        // untouched sections keep their defaults
        assert_eq!(cfg.scanning.min_delay, 1.0);
        assert_eq!(cfg.database.path, default_database_path());
    }

    #[test]
    fn env_overrides_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abyssum.yaml");
        std::fs::write(&path, "server:\n  port: 9999\n").unwrap();

        let env = env_of(&[("ABYSSUM_SERVER_PORT", "12345")]);
        let cfg = Config::load_from(&path, env).unwrap();
        assert_eq!(cfg.server.port, 12345);
    }

    #[test]
    fn env_overrides_apply_across_sections() {
        let env = env_of(&[
            ("ABYSSUM_SERVER_HOST", "0.0.0.0"),
            ("ABYSSUM_DATABASE_PATH", "/var/lib/abyssum/db.sqlite"),
            ("ABYSSUM_SCANNING_MIN_DELAY", "2.5"),
            ("ABYSSUM_SCANNING_MAX_DELAY", "7.0"),
            ("ABYSSUM_SCANNING_MAX_CONCURRENCY", "8"),
            ("ABYSSUM_LOG", "debug"),
        ]);
        let cfg = Config::load_from("/no/such/file.yaml", env).unwrap();
        assert_eq!(cfg.server.host, "0.0.0.0");
        assert_eq!(cfg.database.path, "/var/lib/abyssum/db.sqlite");
        assert_eq!(cfg.scanning.min_delay, 2.5);
        assert_eq!(cfg.scanning.max_delay, 7.0);
        assert_eq!(cfg.scanning.max_concurrency, 8);
        assert_eq!(cfg.log.level, "debug");
    }

    #[test]
    fn malformed_yaml_is_a_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        // Unclosed flow sequence — invalid YAML.
        std::fs::write(&path, "scanning:\n  min_delay: [1, 2\n").unwrap();

        let err = Config::from_file_or_default(&path).unwrap_err();
        assert!(matches!(err, Error::Config(_)), "got {err:?}");
        assert!(err.to_string().contains("configuration error"));
    }

    #[test]
    fn schema_violation_is_a_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        // `port` is a u16; a non-numeric string violates the schema.
        std::fs::write(&path, "server:\n  port: not_a_number\n").unwrap();

        let err = Config::from_file_or_default(&path).unwrap_err();
        assert!(matches!(err, Error::Config(_)), "got {err:?}");
    }

    #[test]
    fn unknown_key_is_a_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "server:\n  bogus_key: 1\n").unwrap();

        let err = Config::from_file_or_default(&path).unwrap_err();
        assert!(matches!(err, Error::Config(_)), "got {err:?}");
    }

    #[test]
    fn invalid_env_value_is_a_config_error() {
        let env = env_of(&[("ABYSSUM_SERVER_PORT", "not_a_port")]);
        let err = Config::load_from("/no/such/file.yaml", env).unwrap_err();
        assert!(matches!(err, Error::Config(_)), "got {err:?}");
    }

    #[test]
    fn abyssum_log_overrides_log_level() {
        let env = env_of(&[("ABYSSUM_LOG", "trace")]);
        let cfg = Config::load_from("/no/such/file.yaml", env).unwrap();
        assert_eq!(cfg.log.level, "trace");
    }

    #[test]
    fn user_agent_rotation_defaults_to_per_request() {
        assert_eq!(
            Config::default().scanning.user_agent_rotation,
            UserAgentRotation::PerRequest
        );
    }

    #[test]
    fn user_agent_rotation_parses_from_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abyssum.yaml");
        std::fs::write(&path, "scanning:\n  user_agent_rotation: per-scan\n").unwrap();

        let cfg = Config::from_file_or_default(&path).unwrap();
        assert_eq!(cfg.scanning.user_agent_rotation, UserAgentRotation::PerScan);
        // Sibling pacing keys keep their conservative defaults.
        assert_eq!(cfg.scanning.min_delay, 1.0);
    }

    #[test]
    fn user_agent_rotation_env_override() {
        let env = env_of(&[("ABYSSUM_SCANNING_USER_AGENT_ROTATION", "per-scan")]);
        let cfg = Config::load_from("/no/such/file.yaml", env).unwrap();
        assert_eq!(cfg.scanning.user_agent_rotation, UserAgentRotation::PerScan);
    }

    #[test]
    fn invalid_user_agent_rotation_is_a_config_error() {
        let env = env_of(&[("ABYSSUM_SCANNING_USER_AGENT_ROTATION", "hourly")]);
        let err = Config::load_from("/no/such/file.yaml", env).unwrap_err();
        assert!(matches!(err, Error::Config(_)), "got {err:?}");
    }

    #[test]
    fn subdomain_bruteforce_defaults_off() {
        // Conservative-by-default: active brute-force is opt-in, so the default
        // must be off. A regression flipping this weakens the stealth posture.
        assert!(!Config::default().scanning.subdomain_bruteforce);
    }

    #[test]
    fn subdomain_bruteforce_parses_from_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abyssum.yaml");
        std::fs::write(&path, "scanning:\n  subdomain_bruteforce: true\n").unwrap();

        let cfg = Config::from_file_or_default(&path).unwrap();
        assert!(cfg.scanning.subdomain_bruteforce);
    }

    #[test]
    fn subdomain_bruteforce_env_override() {
        let env = env_of(&[("ABYSSUM_SCANNING_SUBDOMAIN_BRUTEFORCE", "true")]);
        let cfg = Config::load_from("/no/such/file.yaml", env).unwrap();
        assert!(cfg.scanning.subdomain_bruteforce);
    }

    #[test]
    fn support_lane_defaults_are_fast_and_bounded() {
        let s = Config::default().scanning;
        // Faster than the target floor — that is the whole point of the lane.
        assert!(
            s.support_max_delay < s.min_delay,
            "the support window must beat the target floor"
        );
        // ...but non-zero and bounded, so it is not abusive toward a public service.
        assert!(s.support_min_delay >= 0.0);
        assert!(s.support_max_delay > s.support_min_delay);
        // Higher concurrency posture than target traffic.
        assert!(s.support_max_concurrency >= s.max_concurrency);
    }

    #[test]
    fn support_lane_env_override() {
        let env = env_of(&[
            ("ABYSSUM_SCANNING_SUPPORT_MIN_DELAY", "0.01"),
            ("ABYSSUM_SCANNING_SUPPORT_MAX_DELAY", "0.1"),
            ("ABYSSUM_SCANNING_SUPPORT_MAX_CONCURRENCY", "32"),
        ]);
        let cfg = Config::load_from("/no/such/file.yaml", env).unwrap();
        assert_eq!(cfg.scanning.support_min_delay, 0.01);
        assert_eq!(cfg.scanning.support_max_delay, 0.1);
        assert_eq!(cfg.scanning.support_max_concurrency, 32);
    }

    #[test]
    fn max_wordlist_entries_defaults_and_overrides() {
        assert_eq!(Config::default().scanning.max_wordlist_entries, 2048);
        let env = env_of(&[("ABYSSUM_SCANNING_MAX_WORDLIST_ENTRIES", "50")]);
        let cfg = Config::load_from("/no/such/file.yaml", env).unwrap();
        assert_eq!(cfg.scanning.max_wordlist_entries, 50);
    }

    #[test]
    fn support_lane_parses_from_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abyssum.yaml");
        std::fs::write(&path, "scanning:\n  support_max_delay: 0.5\n").unwrap();

        let cfg = Config::from_file_or_default(&path).unwrap();
        assert_eq!(cfg.scanning.support_max_delay, 0.5);
        // Sibling keys keep their defaults.
        assert_eq!(cfg.scanning.support_min_delay, 0.05);
        assert_eq!(cfg.scanning.min_delay, 1.0);
    }

    #[test]
    fn auth_session_lifetimes_default_and_override() {
        // Conservative defaults: a session cannot outlive a day, and an idle one
        // lapses after an hour.
        let cfg = Config::default();
        assert_eq!(cfg.auth.session_absolute_max_hours, 24);
        assert_eq!(cfg.auth.session_idle_timeout_minutes, 60);

        let env = env_of(&[
            ("ABYSSUM_AUTH_SESSION_ABSOLUTE_MAX_HOURS", "8"),
            ("ABYSSUM_AUTH_SESSION_IDLE_TIMEOUT_MINUTES", "15"),
        ]);
        let cfg = Config::load_from("/no/such/file.yaml", env).unwrap();
        assert_eq!(cfg.auth.session_absolute_max_hours, 8);
        assert_eq!(cfg.auth.session_idle_timeout_minutes, 15);
    }

    #[test]
    fn ai_defaults_are_keyless_and_conservative() {
        let ai = Config::default().ai;
        assert_eq!(ai.base_url, "http://localhost:11434/v1");
        assert_eq!(ai.model, "llama3.1");
        // Keyless by default — the absent-key path must be the default.
        assert!(ai.api_key.is_none());
        assert!(ai.enabled);
        assert_eq!(ai.timeout_seconds, 30);
        assert_eq!(ai.max_evidence_chars, 4000);
        assert_eq!(ai.temperature, 0.2);
        assert!(ai.max_tokens.is_none());
    }

    #[test]
    fn ai_file_overlays_defaults_and_keeps_unset_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abyssum.yaml");
        std::fs::write(
            &path,
            "ai:\n  model: gpt-4o-mini\n  base_url: https://api.openai.example/v1\n",
        )
        .unwrap();

        let cfg = Config::from_file_or_default(&path).unwrap();
        assert_eq!(cfg.ai.model, "gpt-4o-mini");
        assert_eq!(cfg.ai.base_url, "https://api.openai.example/v1");
        // Unset keys in the same section keep their defaults.
        assert_eq!(cfg.ai.timeout_seconds, 30);
        assert_eq!(cfg.ai.max_evidence_chars, 4000);
        assert!(cfg.ai.api_key.is_none());
    }

    #[test]
    fn ai_env_overrides_apply() {
        let env = env_of(&[
            ("ABYSSUM_AI__BASE_URL", "https://other.example/v1"),
            ("ABYSSUM_AI__MODEL", "mixtral"),
            ("ABYSSUM_AI__API_KEY", "sk-secret"),
            ("ABYSSUM_AI__TIMEOUT_SECONDS", "5"),
            ("ABYSSUM_AI__ENABLED", "false"),
            ("ABYSSUM_AI__MAX_EVIDENCE_CHARS", "1000"),
            ("ABYSSUM_AI__TEMPERATURE", "0.7"),
            ("ABYSSUM_AI__MAX_TOKENS", "256"),
        ]);
        let cfg = Config::load_from("/no/such/file.yaml", env).unwrap();
        assert_eq!(cfg.ai.base_url, "https://other.example/v1");
        assert_eq!(cfg.ai.model, "mixtral");
        assert_eq!(cfg.ai.api_key.as_deref(), Some("sk-secret"));
        assert_eq!(cfg.ai.timeout_seconds, 5);
        assert!(!cfg.ai.enabled);
        assert_eq!(cfg.ai.max_evidence_chars, 1000);
        assert_eq!(cfg.ai.temperature, 0.7);
        assert_eq!(cfg.ai.max_tokens, Some(256));
    }

    #[test]
    fn ai_null_and_empty_key_are_both_supported() {
        // Explicit YAML null leaves the key absent.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("abyssum.yaml");
        std::fs::write(&path, "ai:\n  api_key: null\n").unwrap();
        let cfg = Config::from_file_or_default(&path).unwrap();
        assert!(cfg.ai.api_key.is_none());

        // An empty key from the environment is carried verbatim; the AI module is
        // responsible for treating a blank key as "no credential".
        let env = env_of(&[("ABYSSUM_AI__API_KEY", "")]);
        let cfg = Config::load_from("/no/such/file.yaml", env).unwrap();
        assert_eq!(cfg.ai.api_key.as_deref(), Some(""));
    }

    #[test]
    fn defaults_are_conservative() {
        let cfg = Config::default();
        // Non-zero, randomizable pacing window.
        assert!(cfg.scanning.min_delay > 0.0);
        assert!(cfg.scanning.max_delay > 0.0);
        assert!(
            cfg.scanning.max_delay > cfg.scanning.min_delay,
            "max delay must exceed min delay"
        );
        // Bounded, modest concurrency.
        assert!(cfg.scanning.max_concurrency >= 1);
        assert!(cfg.scanning.max_concurrency <= 16);
        // A default database location is present.
        assert!(!cfg.database.path.is_empty());
    }

    #[test]
    fn default_paths_resolve_under_xdg_dirs() {
        // With XDG_*_HOME set to absolute dirs, both defaults resolve beneath
        // them — absolute and independent of the process working directory.
        let cfg_env = env_of(&[("XDG_CONFIG_HOME", "/xdgcfg")]);
        let data_env = env_of(&[("XDG_DATA_HOME", "/xdgdata")]);
        assert_eq!(config_path_from(&cfg_env), "/xdgcfg/abyssum/abyssum.yaml");
        assert_eq!(database_path_from(&data_env), "/xdgdata/abyssum/abyssum.db");
    }

    #[test]
    fn default_paths_fall_back_to_home_when_no_xdg() {
        let env = env_of(&[("HOME", "/home/tester")]);
        assert_eq!(
            config_path_from(&env),
            "/home/tester/.config/abyssum/abyssum.yaml"
        );
        assert_eq!(
            database_path_from(&env),
            "/home/tester/.local/share/abyssum/abyssum.db"
        );
    }

    #[test]
    fn relative_xdg_is_ignored_in_favor_of_home() {
        // A relative XDG value would reintroduce the CWD-relative bug, so the XDG
        // spec says ignore it; HOME takes over and the result stays absolute.
        let env = env_of(&[("XDG_DATA_HOME", "relative/dir"), ("HOME", "/home/tester")]);
        let path = database_path_from(&env);
        assert_eq!(path, "/home/tester/.local/share/abyssum/abyssum.db");
        assert!(Path::new(&path).is_absolute());
    }

    #[test]
    fn missing_home_and_xdg_falls_back_to_relative() {
        // Degenerate environment (no HOME, no XDG): fall back to the historical
        // CWD-relative path rather than panic.
        let env = env_of(&[]);
        assert_eq!(config_path_from(&env), "abyssum.yaml");
        assert_eq!(database_path_from(&env), "data/abyssum.db");
    }

    #[test]
    fn cli_and_web_share_one_default_database() {
        // Both binaries build their `Config` from this crate, so neither defines
        // its own DB default — they share the one resolver by construction.
        assert_eq!(Config::default().database.path, default_database_path());
    }
}
