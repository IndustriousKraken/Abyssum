# Add credential flags to CLI scans

## Why

Real targets — a Hack The Box machine, an authenticated API — require a session to
reach the surface worth testing. The engine already carries an optional
`Credential` (bearer and/or cookie): `Orchestrator::with_credential` attaches it to
every scanner's requests, and BAC/IDOR strip it per-request to compare authorized
vs. unauthorized access. But the `abyssum` CLI exposes no way to supply one, so
every CLI scan runs logged-out. That leaves the authenticated surface untested and
defeats the baseline-vs-stripped design of the BAC and IDOR scanners.

## What Changes

- Add optional `--cookie <value>` and `--bearer <token>` flags to the CLI scan.
- When either is present, build a `Credential` and attach it via the existing
  `Orchestrator::with_credential`.
- When both are absent, behavior is unchanged (scans run unauthenticated).

No engine changes: the credential plumbing, per-request attach, and strip-for-BAC/IDOR
logic already exist. This wires the CLI surface to them.
