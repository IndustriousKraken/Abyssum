# Distribution Delta

## ADDED Requirements

### Requirement: Cross-Compiled Release Artifacts

On a version-tagged release, the system SHALL produce release binaries of both the
command-line and web programs for every supported host platform, each built as a
self-contained binary requiring no separate runtime or interpreter.

#### Scenario: Both binaries built for each supported platform
- **WHEN** a release is produced for a version tag
- **THEN** it SHALL include a command-line binary and a web binary for each supported host
  platform
- **AND** each binary SHALL be named to encode the program name, the release version, and
  the target platform

#### Scenario: Linux binaries honor a minimum platform floor
- **GIVEN** the supported Linux platforms have a fixed minimum system-library floor
- **WHEN** a Linux release binary is produced
- **THEN** the binary SHALL NOT require a system-library version newer than that floor
- **AND** the release process SHALL fail before publishing if a produced Linux binary
  requires a newer version than the floor

#### Scenario: Tests gate the release
- **WHEN** a release build runs
- **THEN** the project test suite SHALL pass before any binary is published
- **AND** a failing test suite SHALL prevent publication

### Requirement: Per-Artifact Checksums

The system SHALL publish a SHA-256 checksum alongside every released binary, and SHALL
verify each checksum against its binary before publication.

#### Scenario: Checksum accompanies every binary
- **WHEN** a release is published
- **THEN** every released binary SHALL have a corresponding SHA-256 checksum file as a
  release asset

#### Scenario: Mismatched checksum blocks publication
- **GIVEN** a computed checksum that does not match its binary
- **WHEN** the release process self-verifies checksums
- **THEN** it SHALL fail
- **AND** SHALL NOT publish the release

### Requirement: Host-Aware Installer

The system SHALL provide an installation script that selects the correct binaries for the
host platform, downloads them with their checksums, and resolves the release version when
one is not specified.

#### Scenario: Selects the matching platform binaries
- **GIVEN** a host whose operating system and architecture map to a supported platform
- **WHEN** the installer runs
- **THEN** it SHALL download the command-line and web binaries built for that platform,
  along with their checksum files

#### Scenario: Resolves the latest version by default
- **GIVEN** no specific version is requested
- **WHEN** the installer runs
- **THEN** it SHALL resolve the most recent published release version and install that

#### Scenario: Unsupported host fails clearly
- **GIVEN** a host whose operating system or architecture has no published binary
- **WHEN** the installer runs
- **THEN** it SHALL report that no pre-built binary exists for that host
- **AND** SHALL exit with a non-zero status without installing anything

### Requirement: Verified Installation Onto PATH

The installer SHALL verify each downloaded binary's checksum before installing it, place
verified binaries on a PATH directory, and refuse to install any binary that fails
verification.

#### Scenario: Verified binaries are installed
- **GIVEN** downloaded binaries whose checksums match their checksum files
- **WHEN** the installer verifies and installs them
- **THEN** verification SHALL succeed
- **AND** both the command-line and web binaries SHALL be placed in a directory on PATH
  and made executable

#### Scenario: Failed verification aborts safely
- **GIVEN** a downloaded binary whose contents do not match its published checksum
- **WHEN** the installer verifies it
- **THEN** the installer SHALL report a verification failure
- **AND** SHALL exit with a non-zero status
- **AND** SHALL NOT place any unverified binary on PATH

#### Scenario: Installation target depends on privilege
- **WHEN** the installer is run with sufficient privilege or as root
- **THEN** it SHALL install into a system-wide PATH directory
- **AND** **WHEN** run without privilege or in user mode it SHALL install into a
  per-user PATH directory instead
