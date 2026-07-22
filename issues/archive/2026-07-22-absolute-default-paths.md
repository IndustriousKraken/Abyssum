# Default config + database paths are CWD-relative — wrong for a PATH-installed binary

## Symptom

The supported install is `install.sh` placing the `abyssum` and `abyssum-web`
binaries on `PATH`, with no source checkout. But both binaries resolve their config
file and database **relative to the current working directory**, so:

- Run `abyssum-web` from `~` and from `~/anything` and you silently get a *different*
  SQLite database (`~/data/abyssum.db` vs `~/anything/data/abyssum.db`) — which reads
  as "my admin account and sessions vanished."
- A scan run with `abyssum` from one directory does not show up in `abyssum-web` (or
  `abyssum report`) launched from another, because they opened different DB files.
- There is no stable, discoverable home for config/data when you never cloned the repo.

## Current behavior

- Database default is relative: `abyssum-core/src/config.rs`, `DatabaseConfig::default`
  → `path: "data/abyssum.db"`.
- Config-file default is the relative `abyssum.yaml`, resolved from CWD, set per binary:
  `abyssum-web/src/main.rs` and `abyssum-cli/src/cli.rs` (both the scan `Cli` and
  `ReportArgs`) use `default_value = "abyssum.yaml"`.

So the "normal" install (binaries on PATH, run from anywhere or via the systemd unit)
has no consistent config or data location unless the operator sets absolute paths by
hand every time.

## Desired behavior

Make the defaults **absolute and CWD-independent**, following platform conventions
(XDG on Linux), while keeping every existing override:

- **Config**: default to `$XDG_CONFIG_HOME/abyssum/abyssum.yaml`
  (i.e. `~/.config/abyssum/abyssum.yaml`), used by *both* binaries. `--config` and
  `ABYSSUM_CONFIG` still override and still win.
- **Database**: default to `$XDG_DATA_HOME/abyssum/abyssum.db`
  (i.e. `~/.local/share/abyssum/abyssum.db`). Because it comes from the shared
  `abyssum-core` config, `abyssum` and `abyssum-web` then use the **same** DB by
  default — so CLI scans appear in the web dashboard with zero configuration.
  `ABYSSUM_DATABASE_PATH` still overrides.
- Create parent directories on first use (persistence already does this for the DB;
  do the same for a first-run config write if any).
- A crate such as `directories` (or `etcetera`) resolves XDG on Linux and the right
  locations on macOS/Windows — implementation choice, not contract.
- Overrides take precedence over the new defaults, so nothing that sets absolute paths
  today changes behavior. In particular `deploy/abyssum-web.service` (which sets
  `ABYSSUM_DATABASE_PATH` and a `StateDirectory`) stays correct.

Related: `embed-web-static-assets` (the same "work as a standalone installed binary,
no source tree" theme, for the web assets).

## How to verify

1. Install only the binaries (no source tree). Run `abyssum-web` from `/`, then from
   `~` → same DB, same config, same admin account both times.
2. `abyssum --targets … --scanners …` from one directory, then `abyssum report <id>`
   and the `abyssum-web` dashboard from a different directory → all see that session
   (one shared default DB).
3. `--config /abs/path.yaml`, `ABYSSUM_CONFIG`, and `ABYSSUM_DATABASE_PATH` still
   override the defaults.
4. First run on a clean machine creates `~/.config/abyssum/` and
   `~/.local/share/abyssum/` as needed without error.

## Tasks

- [x] Resolve a default config path (`$XDG_CONFIG_HOME/abyssum/abyssum.yaml`) in
      `abyssum-core`, and use it as the clap default in both `abyssum-cli` and
      `abyssum-web` instead of the relative `abyssum.yaml`.
- [x] Change `DatabaseConfig::default` to an absolute XDG data path
      (`$XDG_DATA_HOME/abyssum/abyssum.db`).
- [x] Handle a missing `HOME`/XDG environment gracefully (fall back sensibly or emit a
      clear error); ensure `ABYSSUM_*` / `--config` overrides always take precedence.
      (Falls back to the historical CWD-relative path; a relative `XDG_*_HOME` is
      ignored per the XDG spec so the bug can't return.)
- [x] Create parent directories on first use. (Persistence already `create_dir_all`s
      the DB parent; nothing writes a config file, so no config-write path to add.)
- [x] Update the README/config docs (which currently say config is read from the
      working directory) and note the new default locations; mention that existing
      `data/abyssum.db` users can move the file or set `ABYSSUM_DATABASE_PATH`.
- [x] Test: defaults resolve to the same absolute paths regardless of CWD, and CLI +
      web share one DB by default.
