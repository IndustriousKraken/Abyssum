# distribution Specification

## Purpose
TBD - created by archiving change d03-add-distribution. Update Purpose after archive.
## Requirements
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

#### Scenario: Asset names are built from the resolved tag verbatim
- **GIVEN** a resolved release tag string (for example one carrying a leading `v`)
- **WHEN** the installer reconstructs the names of the assets to download
- **THEN** it SHALL use the resolved tag string verbatim, neither stripping nor adding a
  leading `v`
- **AND** the reconstructed names SHALL match the published asset names exactly, because the
  release process names its assets from the same tag string verbatim

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

#### Scenario: Warns when the install directory is not on PATH
- **GIVEN** an install completes into a directory that is not present in the user's PATH
- **WHEN** the installer finishes
- **THEN** it SHALL emit a warning that the install directory is not on PATH
- **AND** the warning SHALL NOT cause the installation to fail

### Requirement: Delivery Machinery Is Linted Before Publishing

The release pipeline SHALL lint its own release workflow and the installer and uninstaller
scripts as part of the pipeline, before any release is published, so a broken workflow or
script is caught in CI rather than at release time.

#### Scenario: Release workflow is linted
- **WHEN** the release pipeline runs
- **THEN** it SHALL lint the release workflow definition with a workflow linter
- **AND** a lint failure SHALL stop the pipeline before any binary is published

#### Scenario: Installer script is linted
- **WHEN** the release pipeline runs
- **THEN** it SHALL lint the installer script with a shell linter
- **AND** a lint failure SHALL stop the pipeline before any binary is published

#### Scenario: Uninstaller script is linted
- **WHEN** the release pipeline runs
- **THEN** it SHALL lint the uninstaller script with a shell linter
- **AND** a lint failure SHALL stop the pipeline before any binary is published

### Requirement: Plain Installation Remains The Default
The installer SHALL, when no controlling terminal is available and no setup flags are given,
install the verified binaries and perform no host configuration — no service, reverse proxy,
firewall, or bind change — so a non-interactive install (CI, cron, or any run with no
controlling terminal, regardless of whether input is piped) installs the binaries only, as
before. Host configuration SHALL happen only when a setup flag is given or a controlling
terminal is available.

#### Scenario: Non-interactive install with no flags installs only binaries
- **GIVEN** the installer runs with no controlling terminal available (a non-interactive context such as CI or cron) and no setup flags
- **WHEN** it runs
- **THEN** it SHALL install the verified binaries
- **AND** it SHALL NOT install a service, a reverse proxy, or change the bind

#### Scenario: Setup requires a terminal or a flag
- **GIVEN** neither a controlling terminal nor any setup flag
- **WHEN** the installer runs
- **THEN** no guided setup SHALL be attempted

### Requirement: Guided Setup Wizard
The installer SHALL, when a controlling terminal is available (including `curl … | bash` from
a real terminal) or when a wizard is explicitly requested, offer optional setup steps after
installing the binaries: running as a service, a TLS reverse proxy, and — when the proxy is
selected — which addresses the proxy serves on plus an optional CIDR restriction. The
installer SHALL NOT offer to bind the web surface to a non-loopback address. Each step SHALL
have a safe default and SHALL be declinable, and declining every step SHALL leave a
binaries-only install.

#### Scenario: Interactive run offers the setup steps
- **GIVEN** the installer runs with a controlling terminal
- **WHEN** the binaries are installed
- **THEN** it SHALL prompt whether to install the service and whether to set up a TLS reverse proxy
- **AND** it SHALL NOT prompt for a bind address for the web surface

#### Scenario: Proxy reach is asked only when the proxy is selected
- **GIVEN** the guided setup is offered
- **WHEN** the operator declines the reverse proxy
- **THEN** no proxy-reach or CIDR question SHALL be asked

#### Scenario: Declining leaves binaries only
- **GIVEN** the guided setup is offered
- **WHEN** the operator declines every step
- **THEN** only the binaries SHALL be installed, with no service or proxy configured

#### Scenario: Each prompt has a default
- **GIVEN** a setup prompt
- **WHEN** it is shown
- **THEN** it SHALL present a default that applies if the operator just accepts it

### Requirement: Non-Interactive Setup Flags
The installer SHALL accept flags that select each guided-setup choice without prompting —
whether to install the service, whether to set up the reverse proxy and for which site, which
addresses the proxy serves on, an optional CIDR restriction, and an assume-yes option — so a
piped or scripted install can perform the full setup unattended. No flag SHALL configure the
web surface to bind a non-loopback address.

#### Scenario: Flags perform setup without prompts
- **GIVEN** the installer is run with setup flags and no terminal
- **WHEN** it runs
- **THEN** it SHALL perform exactly the selected setup without prompting

#### Scenario: Proxy-reach flag configures the proxy, not the app
- **GIVEN** a proxy-reach flag selecting all addresses or loopback only
- **WHEN** setup runs
- **THEN** the proxy SHALL be configured to serve on that reach
- **AND** the web surface SHALL remain bound to loopback

### Requirement: Guided Setup Is Self-Contained And Consistent
The installer SHALL perform any selected setup without requiring a source checkout,
generating the service unit and reverse-proxy configuration itself. Selecting the service
SHALL install, enable, and run it as the instance with the web surface bound to loopback.
Selecting the reverse proxy SHALL install a TLS front end that becomes the network face, with
the chosen reach and any CIDR restriction enforced at the proxy. When no reverse proxy is set
up, the web surface SHALL be reachable only from the host itself.

#### Scenario: Setup needs no source checkout
- **GIVEN** a host that only ran the one-line installer (no repository present)
- **WHEN** setup runs with flags selecting a service and a reverse proxy
- **THEN** the installer SHALL generate and install the service unit and proxy configuration itself

#### Scenario: Service selection runs the app as a service
- **GIVEN** setup selects the service
- **WHEN** it completes
- **THEN** the service SHALL be installed, enabled, and running
- **AND** the web surface SHALL be bound to loopback

#### Scenario: Reverse proxy fronts a localhost app
- **GIVEN** setup selects the reverse proxy
- **WHEN** it completes
- **THEN** the app SHALL remain bound to localhost
- **AND** the proxy SHALL terminate TLS in front of it

#### Scenario: CIDR restriction limits access
- **GIVEN** setup selects the reverse proxy and specifies a CIDR restriction
- **WHEN** it completes
- **THEN** access SHALL be limited to that CIDR range at the proxy

#### Scenario: Without a proxy the web surface is host-only
- **GIVEN** setup installs the service without a reverse proxy
- **WHEN** it completes
- **THEN** the web surface SHALL be reachable only from the host itself

### Requirement: Uninstaller
The project SHALL provide a supported way to remove an installation — an uninstall script
and/or an installer uninstall mode — that removes the installed binaries and any host setup
the installer created (disabling and removing the service, and removing generated
reverse-proxy configuration), preserves user data by default while offering an option to
remove it, and supports a non-interactive confirmation so it can run as a one-liner. Host
state that the installer created but which may be **shared with other software** — such as a
certificate authority added to the system trust store — SHALL be reported to the operator
with the command to remove it, and SHALL NOT be removed by the uninstaller.

#### Scenario: Uninstall removes binaries and created setup
- **GIVEN** an installation that set up a service and a reverse proxy
- **WHEN** the uninstaller runs
- **THEN** it SHALL remove the binaries, disable and remove the service, and remove the generated reverse-proxy configuration

#### Scenario: Shared trust-store state is reported, not removed
- **GIVEN** an uninstall that removes a reverse-proxy configuration whose setup trusted a certificate authority on the host
- **WHEN** the uninstaller runs
- **THEN** it SHALL report that the certificate authority remains in the system trust store, and the command that removes it
- **AND** it SHALL NOT remove that certificate authority itself, because other services on the host may depend on it

#### Scenario: Data is preserved by default
- **GIVEN** an uninstall with no purge option
- **WHEN** it runs
- **THEN** it SHALL leave the user's database and configuration in place

#### Scenario: Purge removes data
- **GIVEN** an uninstall with the purge option
- **WHEN** it runs
- **THEN** it SHALL also remove the user's database and configuration

#### Scenario: Non-interactive confirmation is supported
- **GIVEN** the uninstaller is run with an assume-yes option
- **WHEN** it runs
- **THEN** it SHALL proceed without prompting

