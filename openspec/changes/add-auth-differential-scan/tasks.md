# Tasks

- [ ] Accept two or more named identities on the CLI (repeatable `--identity`),
      each parsed into a label plus an optional `Credential` (cookie and/or bearer);
      a bare label with no credential is the anonymous identity.
- [ ] Run the selected scanners once per identity, attaching that identity's
      credential via `Orchestrator::with_credential`; a single identity behaves as an
      ordinary scan.
- [ ] Ensure every identity's requests route through `ScanContext::send` so the
      pacing floor and User-Agent rotation apply to each pass.
- [ ] Compare per-identity results and emit an access-control finding when a resource
      that appears identity-scoped is reachable by an identity that should not have
      access (horizontal or vertical), reusing BAC/IDOR error-page and body-
      normalization guards to suppress false positives.
- [ ] Persist and render the differential findings like any other findings, naming
      the identities involved in the evidence.
- [ ] Test: a surface where identity-B can read identity-A's resource yields a
      finding; a properly identity-scoped surface yields none.
