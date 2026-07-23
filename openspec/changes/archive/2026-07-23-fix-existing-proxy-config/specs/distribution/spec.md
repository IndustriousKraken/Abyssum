# distribution

## MODIFIED Requirements

### Requirement: Guided Setup Is Self-Contained And Consistent
The installer SHALL perform any selected setup without requiring a source checkout,
generating the service unit and reverse-proxy configuration itself. Selecting the service
SHALL install, enable, and run it as the instance with the web surface bound to loopback.
Selecting the reverse proxy SHALL install a TLS front end that becomes the network face, with
the chosen reach and any CIDR restriction enforced at the proxy. When no reverse proxy is set
up, the web surface SHALL be reachable only from the host itself. The installer SHALL NOT
overwrite a reverse-proxy configuration it did not generate; where such a configuration
prevents the selected proxy settings from being applied, the installer SHALL report that they
were not applied and state how to apply them, and MAY offer to replace that configuration —
after backing it up — when run interactively or when replacement is explicitly requested.

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

#### Scenario: A foreign proxy configuration is never overwritten silently
- **GIVEN** a reverse-proxy configuration on the host that the installer did not generate
- **WHEN** setup selects the reverse proxy without an explicit request to replace it
- **THEN** the installer SHALL leave that configuration unchanged

#### Scenario: Unapplied proxy settings are reported
- **GIVEN** an existing proxy configuration that prevents the selected site, reach, or CIDR restriction from being applied
- **WHEN** setup completes
- **THEN** the installer SHALL report that those settings were not applied
- **AND** SHALL state how to apply them

#### Scenario: Replacing an existing configuration backs it up first
- **GIVEN** replacement of an existing proxy configuration is explicitly requested
- **WHEN** the installer replaces it
- **THEN** it SHALL retain a backup copy of the previous configuration
- **AND** SHALL restore that backup if the generated configuration fails validation
