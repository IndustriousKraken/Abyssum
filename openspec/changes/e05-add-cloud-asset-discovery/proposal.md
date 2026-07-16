# Add forgotten cloud-asset discovery

## Why

Exposed object-storage buckets and stale cloud endpoints are among the most common and
highest-impact forgotten assets — publicly listable buckets leak data outright. Given a
target's domain/organization, guessing likely asset names and probing the cloud providers
surfaces these before an adversary does. On-thesis: the assets people forgot they left
exposed.

## What Changes

- Generate candidate cloud-storage asset names by permuting the target's domain and
  organization identifiers with common affixes.
- Probe known cloud-provider storage endpoints (e.g. S3/GCS/Azure) for each candidate.
- Report assets that exist, and separately (at higher severity) those that are publicly
  readable/listable. Non-existent candidates are not reported.

All probing flows through the existing paced request path.

## Scope line

Confirming existence and public exposure only — the system SHALL NOT download or exfiltrate
asset contents beyond what is needed to confirm the exposure.
