# Add auth-differential scanning

## Why

The access-control bugs that matter most hide in the *difference* between what two
identities can see: user-A reaching user-B's resources (horizontal), or an anonymous
caller reaching a privileged endpoint (vertical). BAC and IDOR already compare one
credentialed baseline against a credential-stripped request, but they cannot compare
two real authenticated identities against each other. With CLI credential flags in
place, the natural next capability is to run the same surface under several named
identities and report where access diverges.

## What Changes

- Accept two or more named **identities** for a scan, each either anonymous (no
  credential) or a credential (cookie and/or bearer).
- Run the selected scanners against the targets once per identity, with every
  identity's requests still flowing through `ScanContext::send` (pacing floor and
  User-Agent rotation preserved — no identity gets an aggression exemption).
- Compare the per-identity results and emit a finding when a resource that should be
  identity-scoped is reachable by an identity that should not have access.

This reuses the existing `Credential` type and orchestrator credential path; it adds
a differential comparison over the per-identity results.
