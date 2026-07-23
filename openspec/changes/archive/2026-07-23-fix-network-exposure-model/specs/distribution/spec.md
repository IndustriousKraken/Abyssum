# distribution

## MODIFIED Requirements

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
