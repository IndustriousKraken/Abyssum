//! Overlaying CLI flags onto the loaded configuration, for this run only.
//!
//! Configuration precedence is `defaults < file < env < CLI flags`: the base
//! [`Config`] already reflects the first three layers (via [`Config::load`]), and
//! this module adds the CLI layer on top. Nothing is written back to disk — the
//! overlay lives only for the invocation.
//!
//! The one nuance is the **pacing floor**. The pre-overlay `min_delay` is treated
//! as a hard floor: the CLI may raise pacing freely, but a supplied minimum below
//! the configured floor is clamped *up* to the floor. This keeps Abyssum's
//! defining principle intact — aggression is opt-in through configuration, not
//! something a single command-line flag can quietly undercut.

use abyssum_core::Config;

/// The optional CLI overrides that overlay the loaded configuration.
#[derive(Debug, Default, Clone)]
pub struct Overrides {
    /// Requested minimum inter-request delay, in seconds.
    pub min_delay: Option<f64>,
    /// Requested maximum inter-request delay, in seconds.
    pub max_delay: Option<f64>,
    /// Requested log verbosity directive.
    pub log_level: Option<String>,
}

/// Apply `overrides` to `config`, returning the configuration for this run.
///
/// `--min-delay` / `--max-delay` set the pacing window and `--log-level` the
/// verbosity, each overriding the loaded value. A supplied minimum below the
/// configured floor (the pre-overlay `min_delay`) is clamped to the floor, and the
/// window is normalized so the maximum is never below the effective minimum.
pub fn apply_overrides(mut config: Config, overrides: &Overrides) -> Config {
    // The configured `min_delay` is the hard floor: CLI flags may raise pacing but
    // never lower it below what the operator configured on disk or via the env.
    let floor = config.scanning.min_delay;

    if let Some(min) = overrides.min_delay {
        config.scanning.min_delay = min.max(floor);
    }
    if let Some(max) = overrides.max_delay {
        config.scanning.max_delay = max;
    }
    // Keep the window coherent: the maximum must not sit below the effective
    // minimum. (`RateLimiter::new` also guards this, but normalizing here keeps the
    // stored config self-consistent for anything that reads it back.)
    if config.scanning.max_delay < config.scanning.min_delay {
        config.scanning.max_delay = config.scanning.min_delay;
    }

    if let Some(level) = &overrides.log_level {
        config.log.level = level.clone();
    }

    config
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Config {
        let mut config = Config::default();
        config.scanning.min_delay = 0.5;
        config.scanning.max_delay = 3.0;
        config.log.level = "warn".to_string();
        config
    }

    #[test]
    fn no_overrides_leaves_config_unchanged() {
        let config = apply_overrides(base(), &Overrides::default());
        assert_eq!(config.scanning.min_delay, 0.5);
        assert_eq!(config.scanning.max_delay, 3.0);
        assert_eq!(config.log.level, "warn");
    }

    #[test]
    fn flags_override_file_and_env_values() {
        // A supplied minimum at or above the floor takes effect, as do max and log.
        let overrides = Overrides {
            min_delay: Some(2.0),
            max_delay: Some(8.0),
            log_level: Some("debug".to_string()),
        };
        let config = apply_overrides(base(), &overrides);
        assert_eq!(config.scanning.min_delay, 2.0);
        assert_eq!(config.scanning.max_delay, 8.0);
        assert_eq!(config.log.level, "debug");
    }

    #[test]
    fn supplied_minimum_below_the_floor_is_clamped_to_the_floor() {
        // floor = 2.0; a supplied 0.1 must not lower pacing below it.
        let mut cfg = base();
        cfg.scanning.min_delay = 2.0;
        let config = apply_overrides(
            cfg,
            &Overrides {
                min_delay: Some(0.1),
                ..Overrides::default()
            },
        );
        assert_eq!(
            config.scanning.min_delay, 2.0,
            "the configured floor takes precedence over a lower supplied minimum"
        );
    }

    #[test]
    fn window_is_normalized_when_max_drops_below_min() {
        let config = apply_overrides(
            base(),
            &Overrides {
                min_delay: Some(4.0),
                max_delay: Some(1.0),
                ..Overrides::default()
            },
        );
        assert_eq!(config.scanning.min_delay, 4.0);
        assert_eq!(
            config.scanning.max_delay, 4.0,
            "max is raised to the effective minimum so the window stays coherent"
        );
    }

    #[test]
    fn overlay_is_for_the_run_only_and_does_not_mutate_the_source() {
        // `apply_overrides` consumes a copy; the caller's config is untouched.
        let source = base();
        let _run = apply_overrides(
            source.clone(),
            &Overrides {
                min_delay: Some(9.0),
                ..Overrides::default()
            },
        );
        assert_eq!(
            source.scanning.min_delay, 0.5,
            "the source config is unchanged"
        );
    }
}
