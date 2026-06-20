# tests-log-level-env-var-fallback-and-precedence

## Coverage gap

`Config::apply_env` resolves the log level from **two** environment-variable
spellings with a defined precedence
(`abyssum-core/src/config.rs:226`):

```rust
if let Some(v) = get_env("ABYSSUM_LOG").or_else(|| get_env("ABYSSUM_LOG_LEVEL")) {
    self.log.level = v;
}
```

`ABYSSUM_LOG` is the documented short form; `ABYSSUM_LOG_LEVEL` is the
sectioned-naming fallback, and the comment states `ABYSSUM_LOG` wins. Only the
short form is tested:

- `abyssum_log_overrides_log_level` (config.rs:364) sets `ABYSSUM_LOG`.
- `env_overrides_apply_across_sections` (config.rs:305) sets `ABYSSUM_LOG`.

The `.or_else(...)` fallback branch (`ABYSSUM_LOG_LEVEL` applies when
`ABYSSUM_LOG` is absent) and the precedence (`ABYSSUM_LOG` wins when both are
present) are **never exercised**. If the fallback branch were dropped,
`ABYSSUM_LOG_LEVEL` would silently stop working; if the order were swapped, the
documented precedence would invert — both with no failing test.

## Source location

- `abyssum-core/src/config.rs` — `apply_env` log-level resolution (226).
- Tests land in the existing `#[cfg(test)] mod tests` in
  `abyssum-core/src/config.rs` (helper `env_of` already exists there).

## Acceptance criteria (against the existing specification)

This asserts already-implemented behavior; it introduces **no** new or changed
contract. Both spellings and the precedence already work — these tests pin them.

Grounded in `openspec/specs/configuration/spec.md`, **Requirement: Configurable
Log Verbosity**, scenario **Log level from environment**:

> - **GIVEN** a log-level environment override set to a debug level
> - **WHEN** the system initializes logging
> - **THEN** log records at that level SHALL be emitted

The configuration layer resolves the effective log level from the environment;
the sectioned `ABYSSUM_LOG_LEVEL` spelling is a valid such override, and when both
spellings are set `ABYSSUM_LOG` takes precedence.

Acceptance: with the injectable `env_of` lookup and `Config::load_from`,
`ABYSSUM_LOG_LEVEL` sets `log.level` when `ABYSSUM_LOG` is unset, and `ABYSSUM_LOG`
sets `log.level` when both are present.
