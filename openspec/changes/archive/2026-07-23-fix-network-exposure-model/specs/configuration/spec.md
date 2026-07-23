# configuration

## ADDED Requirements

### Requirement: Web Surface Binds Loopback By Default
The web surface SHALL bind the loopback address by default, so that an unconfigured
deployment is not reachable from the network. Binding a non-loopback address SHALL require an
explicit configuration setting rather than occurring by default.

#### Scenario: Default bind is loopback
- **GIVEN** no bind address is configured
- **WHEN** the web surface starts
- **THEN** it SHALL listen on the loopback address only

#### Scenario: A network bind requires explicit configuration
- **GIVEN** an operator wants the web surface bound to a non-loopback address
- **WHEN** the web surface starts
- **THEN** that bind SHALL come from an explicit configuration setting
- **AND** SHALL NOT result from the default configuration
