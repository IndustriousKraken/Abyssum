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

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Prefix for all environment-variable configuration overrides.
pub const ENV_PREFIX: &str = "ABYSSUM_";

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
}

/// Web-surface bind settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Host/interface the web surface binds to.
    pub host: String,
    /// TCP port the web surface binds to.
    pub port: u16,
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
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: "data/abyssum.db".to_string(),
        }
    }
}

impl Default for ScanningConfig {
    fn default() -> Self {
        Self {
            min_delay: 1.0,
            max_delay: 3.0,
            max_concurrency: 4,
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
        assert_eq!(cfg.database.path, "data/abyssum.db");
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
        assert_eq!(cfg.database.path, "data/abyssum.db");
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
}
