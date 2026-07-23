# Tasks

- [x] Add a `--force-proxy` flag to `install.sh` that replaces an existing reverse-proxy
      configuration deliberately.
- [x] When `/etc/caddy/Caddyfile` exists and is not abyssum-managed: never overwrite it
      unless `--force-proxy` was given or the operator agrees at an interactive prompt.
- [x] When it is left in place, report explicitly that the chosen site/reach/CIDR were NOT
      applied, and how to apply them (`--force-proxy`, or edit the file) — replacing today's
      "leaving it as-is" message that reads like success.
- [x] When replacing: copy the existing file to a timestamped backup first, and restore that
      backup if `caddy validate` rejects the generated configuration.
- [x] Keep the existing behavior for a foreign Caddyfile that does NOT already front
      abyssum-web: write `abyssum.caddyfile` and say the settings live there pending an
      `import` (now stating plainly that they are not active yet).
- [x] Document `--force-proxy` in the README options list.
- [x] Add a regression guard in `tests/install.test.sh`: the installer must not overwrite a
      non-abyssum-managed proxy config without an explicit force/consent path.
- [ ] Verify on a real host: with a hand-written Caddyfile present, setup reports the
      unapplied settings; `--force-proxy` replaces it and leaves a backup. **Needs a
      sudo-capable run — `setup_proxy` writes `/etc/caddy`.**
