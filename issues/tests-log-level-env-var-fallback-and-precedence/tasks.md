# Tasks: log-level env-var fallback and precedence tests

All tests land in the existing `#[cfg(test)] mod tests` in
`abyssum-core/src/config.rs`, using the in-module `env_of` helper and
`Config::load_from("/no/such/file.yaml", env)` (a nonexistent path, so only the
env layer applies on top of defaults).

- [ ] 1.1 `abyssum_log_level_sectioned_name_sets_level` — with
  `env_of(&[("ABYSSUM_LOG_LEVEL", "debug")])` and `ABYSSUM_LOG` unset, assert the
  loaded `cfg.log.level == "debug"`. Exercises the `.or_else(...)` fallback arm
  (config.rs:226).
- [ ] 1.2 `abyssum_log_takes_precedence_over_log_level` — with
  `env_of(&[("ABYSSUM_LOG", "trace"), ("ABYSSUM_LOG_LEVEL", "warn")])`, assert the
  loaded `cfg.log.level == "trace"`, confirming the short form wins when both
  spellings are present.
- [ ] 1.3 `log_level_defaults_when_neither_env_set` — with an empty `env_of(&[])`
  and no file, assert `cfg.log.level == "info"` (the default), confirming neither
  branch fires when both spellings are absent.
