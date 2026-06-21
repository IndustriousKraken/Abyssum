//! Structured logging initialization.
//!
//! Both binaries call [`init`] once on startup. The verbosity filter comes from
//! the loaded [`Config`] (`log.level`), which itself already reflects the
//! `ABYSSUM_LOG` environment override applied during configuration loading — so
//! there is a single, well-defined source of truth for log level.

use std::sync::Once;

use tracing_subscriber::{fmt, EnvFilter};

use crate::config::Config;

static INIT: Once = Once::new();

/// Initialize the global tracing subscriber from `config`.
///
/// Idempotent: safe to call more than once (e.g. from tests or repeated
/// startup paths); only the first call installs a subscriber. The level string
/// is parsed as a `tracing-subscriber` `EnvFilter` directive, so values like
/// `debug` or `abyssum_core=debug,info` both work; an unparsable value falls
/// back to `info` rather than failing startup.
pub fn init(config: &Config) {
    INIT.call_once(|| {
        let filter = build_filter(&config.log.level);
        // `try_init` returns Err if a global subscriber is already installed
        // (e.g. by a test harness); that is fine to ignore.
        let _ = fmt().with_env_filter(filter).try_init();
    });
}

/// Build an [`EnvFilter`] from a level directive, defaulting to `info` if the
/// directive cannot be parsed.
fn build_filter(level: &str) -> EnvFilter {
    EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_filter_accepts_plain_levels() {
        // Should not panic / fall back for ordinary level names.
        for level in ["error", "warn", "info", "debug", "trace"] {
            let filter = build_filter(level);
            assert_eq!(filter.to_string(), level);
        }
    }

    #[test]
    fn build_filter_accepts_targeted_directives() {
        let filter = build_filter("abyssum_core=debug,info");
        assert!(filter.to_string().contains("abyssum_core"));
    }

    #[test]
    fn build_filter_falls_back_on_garbage() {
        // A clearly invalid directive must not panic; it falls back to info.
        let filter = build_filter("=(not a filter)=");
        assert_eq!(filter.to_string(), "info");
    }

    #[test]
    fn init_is_idempotent() {
        let cfg = Config::default();
        init(&cfg);
        init(&cfg); // second call must be a no-op, not a panic
    }
}
