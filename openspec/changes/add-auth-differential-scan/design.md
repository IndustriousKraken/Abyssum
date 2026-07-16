# Design

## Identities

An identity is a label plus an optional `Credential` (the existing
`{ bearer, cookie }`). The anonymous identity carries no credential. Reuse the CLI
credential flags from `add-cli-scan-credentials`; a repeatable `--identity
<label>[:cookie=…][:bearer=…]` form names each one. Two or more identities trigger a
differential run; a single identity is an ordinary scan (unchanged).

## Execution

Run the selected scanners once per identity, attaching that identity's credential via
`Orchestrator::with_credential`. Every request still goes through `ScanContext::send`,
so pacing and UA rotation apply per identity exactly as for a normal scan — N
identities means N passes of paced traffic, not a burst.

## Differential comparison

Compare per-endpoint responses across identities. Report a finding when:

- a resource is served with equivalent privileged content to more than one identity
  where it appears identity-scoped (horizontal — user-A sees user-B's data), or
- an endpoint denied to a higher-privilege expectation is nonetheless reachable by a
  lower-privilege or anonymous identity (vertical).

Reuse the false-positive guards already proven in BAC/IDOR: error-page and
soft-404 fingerprinting, and body normalization (whitespace-normalized / JSON-aware)
so that identical error or login-redirect pages are not mistaken for shared access.

Detection heuristics are guidance here, not contract; the binding behavior is in the
spec delta.
