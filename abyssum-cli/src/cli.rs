//! The `abyssum` argument parser.
//!
//! Targets and scanners are **repeatable** flags (`--targets URL --targets URL`,
//! `--scanners ID --scanners ID`), each required at least once. Pacing and log
//! level are optional overrides that overlay the loaded configuration for this
//! run only (see [`crate::config_overlay`]); the output format is restricted to
//! `table` / `json` / `csv` by a [`ValueEnum`]. `clap` itself serves `--help` and
//! `--version` and exits `0`.

use clap::{Parser, ValueEnum};

/// Abyssum: a patient, stealthy API vulnerability scanner for **authorized**
/// security testing only.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "abyssum",
    version,
    about = "Abyssum — API vulnerability scanner for authorized testing",
    long_about = None
)]
pub struct Cli {
    /// Target URL to scan. Repeatable; a bare host (no scheme) is treated as
    /// `https`. At least one is required.
    #[arg(
        long = "targets",
        value_name = "URL",
        required = true,
        action = clap::ArgAction::Append
    )]
    pub targets: Vec<String>,

    /// Scanner id to run (e.g. `cors`, `rest_discovery`). Repeatable; validated
    /// against the registry's available ids. At least one is required.
    #[arg(
        long = "scanners",
        value_name = "ID",
        required = true,
        action = clap::ArgAction::Append
    )]
    pub scanners: Vec<String>,

    /// Minimum inter-request delay, in seconds. Overrides the configured value for
    /// this run, but never paces below the configured floor (see the project's
    /// stealth philosophy).
    #[arg(long, value_name = "SECONDS")]
    pub min_delay: Option<f64>,

    /// Maximum inter-request delay, in seconds. Overrides the configured value for
    /// this run.
    #[arg(long, value_name = "SECONDS")]
    pub max_delay: Option<f64>,

    /// Log verbosity for this run (e.g. `info`, `debug`, or a targeted directive
    /// like `abyssum_core=debug,info`). Overrides the configured level.
    #[arg(long, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Output format for the findings.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,

    /// Path to the YAML configuration file (a missing file falls back to built-in
    /// defaults).
    #[arg(
        long,
        value_name = "PATH",
        env = "ABYSSUM_CONFIG",
        default_value = "abyssum.yaml"
    )]
    pub config: String,
}

/// How the run's findings are rendered. Restricted to these three by `clap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// A human-readable aligned table (the default).
    Table,
    /// Machine-readable JSON.
    Json,
    /// CSV with a stable header row.
    Csv,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--targets`/`--scanners` are repeatable and at least one of each is
    /// required; `--output` defaults to the table.
    #[test]
    fn parses_repeatable_targets_and_scanners() {
        let cli = Cli::try_parse_from([
            "abyssum",
            "--targets",
            "https://a.test",
            "--targets",
            "b.test",
            "--scanners",
            "cors",
            "--scanners",
            "rest_discovery",
        ])
        .unwrap();
        assert_eq!(cli.targets, vec!["https://a.test", "b.test"]);
        assert_eq!(cli.scanners, vec!["cors", "rest_discovery"]);
        assert_eq!(cli.output, OutputFormat::Table);
        assert!(cli.min_delay.is_none());
    }

    /// At least one target is required.
    #[test]
    fn requires_a_target() {
        let err = Cli::try_parse_from(["abyssum", "--scanners", "cors"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    /// At least one scanner is required.
    #[test]
    fn requires_a_scanner() {
        let err = Cli::try_parse_from(["abyssum", "--targets", "a.test"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    /// `--output` is restricted to the three known formats.
    #[test]
    fn output_is_restricted_to_known_formats() {
        for (flag, expected) in [
            ("table", OutputFormat::Table),
            ("json", OutputFormat::Json),
            ("csv", OutputFormat::Csv),
        ] {
            let cli = Cli::try_parse_from([
                "abyssum",
                "--targets",
                "a.test",
                "--scanners",
                "cors",
                "--output",
                flag,
            ])
            .unwrap();
            assert_eq!(cli.output, expected);
        }
        let err = Cli::try_parse_from([
            "abyssum",
            "--targets",
            "a.test",
            "--scanners",
            "cors",
            "--output",
            "xml",
        ])
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
    }

    /// Pacing and log-level overrides parse into their option fields.
    #[test]
    fn parses_pacing_and_log_overrides() {
        let cli = Cli::try_parse_from([
            "abyssum",
            "--targets",
            "a.test",
            "--scanners",
            "cors",
            "--min-delay",
            "2.5",
            "--max-delay",
            "7",
            "--log-level",
            "debug",
        ])
        .unwrap();
        assert_eq!(cli.min_delay, Some(2.5));
        assert_eq!(cli.max_delay, Some(7.0));
        assert_eq!(cli.log_level.as_deref(), Some("debug"));
    }
}
