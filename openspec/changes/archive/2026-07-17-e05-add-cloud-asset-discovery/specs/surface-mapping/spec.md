# surface-mapping

## ADDED Requirements

### Requirement: Discover Exposed Cloud Storage Assets
The system SHALL discover candidate cloud-storage assets for a target by generating
candidate names from the target's domain and organization identifiers and probing known
cloud-provider storage endpoints, and SHALL report assets that exist — reporting those
that are publicly readable or listable at high severity as a data-exposure finding. A
candidate that does not exist SHALL NOT be reported. The system SHALL confirm existence
and exposure only, and SHALL NOT download or enumerate asset contents beyond what is
needed to confirm exposure. All probing SHALL pass through the paced request path.

#### Scenario: A publicly listable asset is reported at high severity
- **GIVEN** a candidate that resolves to an existing, publicly readable/listable storage asset
- **WHEN** cloud-asset discovery probes it
- **THEN** it SHALL be reported as a high-severity data-exposure finding

#### Scenario: An existing but access-denied asset is reported as footprint
- **GIVEN** a candidate that exists but returns access-denied
- **WHEN** cloud-asset discovery probes it
- **THEN** it SHALL be reported as an informational finding recording the asset

#### Scenario: A non-existent candidate is not reported
- **GIVEN** a candidate that does not correspond to any asset
- **WHEN** cloud-asset discovery probes it
- **THEN** it SHALL NOT be reported

#### Scenario: Exposure is confirmed without exfiltration
- **GIVEN** a publicly readable asset
- **WHEN** the system confirms its exposure
- **THEN** it SHALL NOT download or enumerate the asset's contents beyond what confirms the exposure
