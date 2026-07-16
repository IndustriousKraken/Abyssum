//! The `abyssum` argument parser.
//!
//! Targets and scanners are **repeatable** flags (`--targets URL --targets URL`,
//! `--scanners ID --scanners ID`), each required at least once. Pacing and log
//! level are optional overrides that overlay the loaded configuration for this
//! run only (see [`crate::config_overlay`]); the output format is restricted to
//! `table` / `json` / `csv` by a [`ValueEnum`]. `clap` itself serves `--help` and
//! `--version` and exits `0`.

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Abyssum: a patient, stealthy API vulnerability scanner for **authorized**
/// security testing only.
///
/// With no subcommand the CLI runs a scan (its top-level `--targets`/`--scanners`
/// flags). The `report` subcommand renders stored sessions; when it is present the
/// scan flags are not required (`subcommand_negates_reqs`).
#[derive(Debug, Clone, Parser)]
#[command(
    name = "abyssum",
    version,
    about = "Abyssum — API vulnerability scanner for authorized testing",
    long_about = None,
    subcommand_negates_reqs = true
)]
pub struct Cli {
    /// Optional subcommand. Absent → run a scan from the top-level flags below.
    #[command(subcommand)]
    pub command: Option<Command>,

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

    /// A named identity to scan as, `label[:cookie=VALUE][:bearer=TOKEN]`.
    /// Repeatable. A bare `label` (no credential) is the anonymous identity. Supply
    /// **two or more** to trigger an auth-differential run: the selected scanners
    /// run once per identity and access-control divergence is reported. A single
    /// identity is an ordinary scan carrying that identity's credential. Cookie and
    /// bearer values must not contain a colon. A differential run reports only
    /// access-control divergence between identities — not the underlying scanners'
    /// own findings (discovered endpoints, CORS misconfigurations, etc.).
    #[arg(long = "identity", value_name = "SPEC", action = clap::ArgAction::Append)]
    pub identities: Vec<String>,

    /// Cookie header value sent with every credentialed request (e.g.
    /// `session=abc123`). Optional and independent of `--bearer`: supply either,
    /// both, or neither. Scanners whose contract requires an unauthenticated probe
    /// (BAC, IDOR) omit it regardless.
    #[arg(long, value_name = "VALUE")]
    pub cookie: Option<String>,

    /// Bearer token sent as `Authorization: Bearer <token>` on every credentialed
    /// request. Optional and independent of `--cookie`: supply either, both, or
    /// neither. Note: a secret passed here (like `--cookie`) is visible to other
    /// local users via the process table and is retained in shell history — avoid
    /// it on shared hosts.
    #[arg(long, value_name = "TOKEN")]
    pub bearer: Option<String>,

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

/// The CLI's subcommands. Scanning is the no-subcommand default; this carries the
/// non-scan operations.
#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Generate a report for one or more stored scan sessions.
    Report(ReportArgs),
    /// Diff two stored scan sessions, reporting what changed between them.
    Diff(DiffArgs),
}

/// Arguments to the `diff` subcommand.
#[derive(Debug, Clone, Args)]
pub struct DiffArgs {
    /// The older (baseline) session id.
    #[arg(value_name = "OLDER_SESSION")]
    pub older: String,

    /// The newer session id to compare against the baseline.
    #[arg(value_name = "NEWER_SESSION")]
    pub newer: String,

    /// Output format for the diff.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub output: OutputFormat,

    /// Path to the YAML configuration file (locates the result store).
    #[arg(
        long,
        value_name = "PATH",
        env = "ABYSSUM_CONFIG",
        default_value = "abyssum.yaml"
    )]
    pub config: String,
}

/// Arguments to the `report` subcommand.
#[derive(Debug, Clone, Args)]
pub struct ReportArgs {
    /// Session id(s) to report on. `markdown`/`hackerone` take exactly one;
    /// `json`/`csv` take one or more. At least one is required.
    #[arg(value_name = "SESSION_ID", required = true)]
    pub sessions: Vec<String>,

    /// Report format.
    #[arg(long, value_enum, default_value_t = ReportFormat::Markdown)]
    pub format: ReportFormat,

    /// Write the report to this file instead of standard output.
    #[arg(long, value_name = "FILE")]
    pub output: Option<String>,

    /// Omit finding evidence from the report (a redacted/short report). Evidence is
    /// included by default; CSV never carries evidence regardless.
    #[arg(long = "no-evidence")]
    pub no_evidence: bool,

    /// Path to the YAML configuration file (locates the result store).
    #[arg(
        long,
        value_name = "PATH",
        env = "ABYSSUM_CONFIG",
        default_value = "abyssum.yaml"
    )]
    pub config: String,
}

/// The report output form. Restricted to these four by `clap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    /// A self-contained Markdown submission report (single session).
    Markdown,
    /// A structured JSON export (one or more sessions).
    Json,
    /// A flat CSV summary (one or more sessions).
    Csv,
    /// A HackerOne-shaped submission (single session).
    Hackerone,
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

    /// A bare scan invocation leaves `command` unset.
    #[test]
    fn scan_invocation_has_no_subcommand() {
        let cli =
            Cli::try_parse_from(["abyssum", "--targets", "a.test", "--scanners", "cors"]).unwrap();
        assert!(cli.command.is_none());
    }

    /// The `report` subcommand parses its session id, format, output, and
    /// evidence-omission flag, and does not require the scan flags.
    #[test]
    fn parses_report_subcommand() {
        let cli = Cli::try_parse_from([
            "abyssum",
            "report",
            "11111111-1111-1111-1111-111111111111",
            "--format",
            "hackerone",
            "--output",
            "out.md",
            "--no-evidence",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Report(args)) => {
                assert_eq!(args.sessions, vec!["11111111-1111-1111-1111-111111111111"]);
                assert_eq!(args.format, ReportFormat::Hackerone);
                assert_eq!(args.output.as_deref(), Some("out.md"));
                assert!(args.no_evidence);
            }
            other => panic!("expected a report command, got {other:?}"),
        }
    }

    /// `report` accepts several session ids (for the json/csv formats) and defaults
    /// to markdown with evidence included.
    #[test]
    fn report_accepts_multiple_sessions_and_defaults() {
        let cli =
            Cli::try_parse_from(["abyssum", "report", "id-a", "id-b", "--format", "json"]).unwrap();
        let Some(Command::Report(args)) = cli.command else {
            panic!("expected a report command");
        };
        assert_eq!(args.sessions, vec!["id-a", "id-b"]);
        assert_eq!(args.format, ReportFormat::Json);
        assert!(args.output.is_none());
        assert!(!args.no_evidence);
    }

    /// `report` requires at least one session id.
    #[test]
    fn report_requires_a_session_id() {
        let err = Cli::try_parse_from(["abyssum", "report"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    /// The `diff` subcommand parses the older/newer session ids and its output
    /// format, and does not require the scan flags.
    #[test]
    fn parses_diff_subcommand() {
        let cli = Cli::try_parse_from([
            "abyssum",
            "diff",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "--output",
            "json",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Diff(args)) => {
                assert_eq!(args.older, "11111111-1111-1111-1111-111111111111");
                assert_eq!(args.newer, "22222222-2222-2222-2222-222222222222");
                assert_eq!(args.output, OutputFormat::Json);
            }
            other => panic!("expected a diff command, got {other:?}"),
        }
    }

    /// `diff` defaults `--output` to the table.
    #[test]
    fn diff_defaults_output_to_table() {
        let cli = Cli::try_parse_from(["abyssum", "diff", "id-a", "id-b"]).unwrap();
        let Some(Command::Diff(args)) = cli.command else {
            panic!("expected a diff command");
        };
        assert_eq!(args.output, OutputFormat::Table);
    }

    /// `diff` requires both the older and newer session ids.
    #[test]
    fn diff_requires_both_sessions() {
        let err = Cli::try_parse_from(["abyssum", "diff", "only-one"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
    }

    /// `--identity` is repeatable and captures each raw spec verbatim (parsing of
    /// the `label:cookie=…:bearer=…` form happens in the run layer).
    #[test]
    fn parses_repeatable_identities() {
        let cli = Cli::try_parse_from([
            "abyssum",
            "--targets",
            "a.test",
            "--scanners",
            "rest_discovery",
            "--identity",
            "alice:bearer=tok-a",
            "--identity",
            "bob:cookie=session=b",
            "--identity",
            "guest",
        ])
        .unwrap();
        assert_eq!(
            cli.identities,
            vec!["alice:bearer=tok-a", "bob:cookie=session=b", "guest"]
        );
    }

    /// Omitting `--identity` leaves the list empty (an ordinary, credential-free scan).
    #[test]
    fn identities_default_empty() {
        let cli =
            Cli::try_parse_from(["abyssum", "--targets", "a.test", "--scanners", "cors"]).unwrap();
        assert!(cli.identities.is_empty());
    }

    /// `--cookie` and `--bearer` parse into their option fields and default to
    /// `None` (an unauthenticated scan).
    #[test]
    fn parses_credential_flags() {
        let cli = Cli::try_parse_from([
            "abyssum",
            "--targets",
            "a.test",
            "--scanners",
            "cors",
            "--cookie",
            "session=abc123",
            "--bearer",
            "tok-secret",
        ])
        .unwrap();
        assert_eq!(cli.cookie.as_deref(), Some("session=abc123"));
        assert_eq!(cli.bearer.as_deref(), Some("tok-secret"));

        let bare =
            Cli::try_parse_from(["abyssum", "--targets", "a.test", "--scanners", "cors"]).unwrap();
        assert!(bare.cookie.is_none());
        assert!(bare.bearer.is_none());
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
