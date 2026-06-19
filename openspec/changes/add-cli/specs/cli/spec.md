# CLI Delta

## ADDED Requirements

### Requirement: Select Scanners And Targets
The command-line interface SHALL accept one or more target URLs and one or more scanner ids,
and SHALL run each selected scanner against each target through the shared scan engine.

#### Scenario: Single scanner against a single target
- **WHEN** the operator invokes the CLI with one target and one scanner id
- **THEN** that scanner SHALL run against that target
- **AND** the run SHALL produce the scanner's findings

#### Scenario: Multiple scanners against multiple targets
- **WHEN** the operator invokes the CLI with several targets and several scanner ids
- **THEN** every selected scanner SHALL run against every target
- **AND** the findings from all combinations SHALL be reported together

#### Scenario: Default scheme is applied to a bare target
- **GIVEN** a target given without a URL scheme
- **WHEN** the CLI parses the target
- **THEN** it SHALL treat the target as an `https` URL

### Requirement: Reject Invalid Input Before Scanning
The CLI SHALL validate targets and scanner ids before issuing any request and SHALL refuse
to start when input is invalid.

#### Scenario: Unknown scanner id
- **WHEN** the operator requests a scanner id that is not registered
- **THEN** the CLI SHALL report that the scanner is unknown
- **AND** SHALL NOT issue any request
- **AND** SHALL exit with a non-zero status

#### Scenario: Unparseable target
- **WHEN** a supplied target cannot be parsed as a valid URL
- **THEN** the CLI SHALL report the invalid target
- **AND** SHALL NOT issue any request
- **AND** SHALL exit with a non-zero status

### Requirement: Configure Pacing And Verbosity By Flag
The CLI SHALL expose flags that set the request pacing window and the log verbosity for the
run, overriding the corresponding configuration values, without ever pacing faster than the
configured floor.

#### Scenario: Pacing flags set the delay window
- **GIVEN** minimum- and maximum-delay flags are supplied
- **WHEN** the scan runs
- **THEN** requests to a domain SHALL be paced within the supplied window
- **AND** no request SHALL be issued before the supplied minimum delay has elapsed since the
  previous request to that domain

#### Scenario: Log level controls verbosity
- **GIVEN** a log-level flag set to a more verbose level
- **WHEN** the CLI runs
- **THEN** log output at that level SHALL be emitted

#### Scenario: Flags override configuration for the run
- **GIVEN** a configuration file or environment sets a pacing or log value
- **AND** a CLI flag sets a different value
- **WHEN** the CLI runs
- **THEN** the flag value SHALL take effect for that run

### Requirement: Multiple Output Formats
The CLI SHALL render the run's findings in a human-readable table, as JSON, or as CSV,
selected by a flag, where every format reflects the same underlying findings.

#### Scenario: Table output by default
- **WHEN** the operator runs a scan without selecting an output format
- **THEN** the findings SHALL be printed as a human-readable table
- **AND** the table SHALL show, per finding, the scanner, target, status, severity, and title

#### Scenario: JSON output
- **WHEN** the operator selects JSON output
- **THEN** the findings SHALL be printed as machine-readable JSON

#### Scenario: CSV output
- **WHEN** the operator selects CSV output
- **THEN** the findings SHALL be printed as CSV with a stable header row
- **AND** fields containing commas or newlines SHALL be escaped so the output stays parseable

#### Scenario: Formats agree on content
- **GIVEN** a completed scan with findings
- **WHEN** the same run is rendered in each format
- **THEN** every format SHALL represent the same set of findings

### Requirement: CLI Scans Are Persisted
A CLI run SHALL create a scan session and store its findings through the persistence layer,
so command-line scans are retrievable and survive restart like any other scan.

#### Scenario: Run is stored
- **WHEN** a CLI scan completes
- **THEN** a scan session for the run SHALL exist in persistence
- **AND** the run's findings SHALL be retrievable from persistence

#### Scenario: Stored run survives restart
- **GIVEN** a CLI scan has completed and been persisted
- **WHEN** the persistence layer is reopened
- **THEN** the session and its findings SHALL still be retrievable

### Requirement: Exit Status Reflects Outcome
The CLI process SHALL exit with status 0 when the scan completes and with a non-zero status
when the run fails or is interrupted.

#### Scenario: Successful scan
- **WHEN** a scan completes without error
- **THEN** the process SHALL exit with status 0

#### Scenario: Failed or interrupted run
- **WHEN** the run fails due to an error or is interrupted before completion
- **THEN** the process SHALL exit with a non-zero status
