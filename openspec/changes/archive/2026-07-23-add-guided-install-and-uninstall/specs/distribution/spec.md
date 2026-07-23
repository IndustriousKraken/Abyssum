# distribution

## ADDED Requirements

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
installing the binaries: running as a service, how the web interface is exposed on the
network, and a TLS reverse proxy. Each step SHALL have a safe default and SHALL be
declinable, and declining every step SHALL leave a binaries-only install.

#### Scenario: Interactive run offers the setup steps
- **GIVEN** the installer runs with a controlling terminal
- **WHEN** the binaries are installed
- **THEN** it SHALL prompt whether to install the service, how to expose the web interface, and whether to set up a TLS reverse proxy

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
whether to install the service, how to expose the web interface (localhost only, all
interfaces, or a specific address, with an optional CIDR restriction), whether to set up the
reverse proxy and for which site, and an assume-yes option — so a piped or scripted install
can perform the full setup unattended.

#### Scenario: Flags perform setup without prompts
- **GIVEN** the installer is run with setup flags and no terminal
- **WHEN** it runs
- **THEN** it SHALL perform exactly the selected setup without prompting

#### Scenario: Exposure flag binds the app when it is exposed directly
- **GIVEN** an exposure flag set to localhost, all interfaces, or a specific address, and no reverse proxy is set up
- **WHEN** setup runs
- **THEN** the web interface SHALL be configured to bind accordingly

### Requirement: Guided Setup Is Self-Contained And Consistent
The installer SHALL perform any selected setup without requiring a source checkout,
generating the service unit and reverse-proxy configuration itself. Selecting the service
SHALL install, enable, and run it as the instance. When no reverse proxy is set up, the
exposure choice SHALL determine how the app binds. Selecting the reverse proxy SHALL install
a TLS front end, keep the app bound to localhost regardless of the exposure flag, and become
the network face — with the exposure reach and any CIDR restriction enforced at the proxy.

#### Scenario: Setup needs no source checkout
- **GIVEN** a host that only ran the one-line installer (no repository present)
- **WHEN** setup runs with flags selecting a service and a reverse proxy
- **THEN** the installer SHALL generate and install the service unit and proxy configuration itself

#### Scenario: Service selection runs the app as a service
- **GIVEN** setup selects the service
- **WHEN** it completes
- **THEN** the service SHALL be installed, enabled, and running

#### Scenario: Reverse proxy fronts a localhost app
- **GIVEN** setup selects the reverse proxy
- **WHEN** it completes
- **THEN** the app SHALL remain bound to localhost
- **AND** the proxy SHALL terminate TLS in front of it

#### Scenario: CIDR restriction limits access
- **GIVEN** setup exposes the interface and specifies a CIDR restriction
- **WHEN** it completes
- **THEN** access SHALL be limited to that CIDR range

### Requirement: Uninstaller
The project SHALL provide a supported way to remove an installation — an uninstall script
and/or an installer uninstall mode — that removes the installed binaries and any host setup
the installer created (disabling and removing the service, and removing generated
reverse-proxy configuration), preserves user data by default while offering an option to
remove it, and supports a non-interactive confirmation so it can run as a one-liner.

#### Scenario: Uninstall removes binaries and created setup
- **GIVEN** an installation that set up a service and a reverse proxy
- **WHEN** the uninstaller runs
- **THEN** it SHALL remove the binaries, disable and remove the service, and remove the generated reverse-proxy configuration

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

## MODIFIED Requirements

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
