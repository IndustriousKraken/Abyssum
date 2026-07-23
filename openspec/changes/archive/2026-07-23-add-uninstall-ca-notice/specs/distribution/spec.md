# distribution

## MODIFIED Requirements

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
