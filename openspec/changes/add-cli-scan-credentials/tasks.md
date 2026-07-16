# Tasks

- [ ] Add optional `--cookie <value>` and `--bearer <token>` args to the CLI arg
      struct (`abyssum-cli/src/cli.rs`), documented as optional and mutually
      independent (either, both, or neither).
- [ ] In the run path (`abyssum-cli/src/run.rs`), when either flag is set, build a
      `Credential` from the provided bearer and/or cookie and attach it with
      `Orchestrator::with_credential` before running the session.
- [ ] When neither flag is set, do not attach a credential (scan runs
      unauthenticated — unchanged behavior).
- [ ] Test: a scan invoked with `--cookie`/`--bearer` sends the credential on
      scanner requests; a scan invoked with neither sends none.
