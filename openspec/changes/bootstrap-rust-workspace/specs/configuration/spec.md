# Configuration Delta

## ADDED Requirements

### Requirement: Layered Configuration Loading
The system SHALL determine its runtime configuration by layering three sources in strict
precedence: built-in defaults, an optional YAML configuration file, and environment
variable overrides, where each later source overrides the earlier.

#### Scenario: Defaults when no file or env present
- **GIVEN** no configuration file exists at the configured path
- **AND** no `ABYSSUM_*` environment variables are set
- **WHEN** the system loads configuration
- **THEN** it SHALL use built-in default values
- **AND** startup SHALL succeed

#### Scenario: File overlays defaults
- **GIVEN** a valid YAML configuration file specifying a non-default server port
- **WHEN** the system loads configuration
- **THEN** the file's value SHALL replace the corresponding default
- **AND** keys absent from the file SHALL retain their default values

#### Scenario: Environment overrides file
- **GIVEN** a YAML file sets the server port
- **AND** a `ABYSSUM_*` environment variable sets a different server port
- **WHEN** the system loads configuration
- **THEN** the environment variable value SHALL take effect

### Requirement: Fail-Fast on Invalid Configuration
The system SHALL refuse to start when configuration is present but malformed, reporting a
clear error rather than starting with partial or default values.

#### Scenario: Malformed configuration file
- **GIVEN** a configuration file that is not valid YAML or violates the expected schema
- **WHEN** the system loads configuration
- **THEN** it SHALL return a configuration error identifying the problem
- **AND** the process SHALL NOT continue startup

#### Scenario: Missing file is not an error
- **GIVEN** no configuration file exists at the configured path
- **WHEN** the system loads configuration
- **THEN** loading SHALL succeed using defaults and any environment overrides

### Requirement: Conservative Default Configuration
The system's built-in default configuration SHALL be conservative, so that running with no
tuning neither overwhelms a target nor scans aggressively. This encodes the project's
stealth-and-respect philosophy as the default posture.

#### Scenario: Default pacing is non-zero and randomized
- **WHEN** the system loads configuration with no overrides
- **THEN** the default minimum and maximum inter-request delays SHALL both be greater than zero
- **AND** the default maximum delay SHALL be greater than the default minimum delay

#### Scenario: Default concurrency is bounded
- **WHEN** the system loads configuration with no overrides
- **THEN** the default limit on concurrent requests SHALL be a finite, modest value
- **AND** aggressive settings SHALL require an explicit override by the user

### Requirement: Runnable Binary Entry Points
The system SHALL provide command-line and web binaries that start, report their version and
usage on request, and exit cleanly.

#### Scenario: Version flag
- **WHEN** either binary is invoked with `--version`
- **THEN** it SHALL print its version
- **AND** exit with status 0

#### Scenario: Help flag
- **WHEN** either binary is invoked with `--help`
- **THEN** it SHALL print usage information
- **AND** exit with status 0

### Requirement: Configurable Log Verbosity
The system SHALL emit structured logs whose verbosity is controlled by configuration and
overridable by environment.

#### Scenario: Log level from environment
- **GIVEN** a log-level environment override set to a debug level
- **WHEN** the system initializes logging
- **THEN** log records at that level SHALL be emitted
