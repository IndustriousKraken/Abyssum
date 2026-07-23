# Tasks

- [x] Keep the piped/no-terminal, no-flags path installing binaries only (unchanged one-liner).
- [x] Detect a controlling terminal and, unless `--no-wizard`, run a guided setup after
      installing binaries: service? / exposure (localhost | all | specific address, plus an
      optional CIDR restriction)? / TLS reverse proxy (+ site)? Each prompt defaulted and
      declinable; read prompts from `/dev/tty` so `curl … | bash` stays interactive.
- [x] Add non-interactive flags mirroring every prompt (`--service`, `--expose`,
      `--allow-cidr`, `--proxy`, `--site`, `--yes`, `--no-wizard`); any setup flag implies
      non-interactive setup.
- [x] Generate the systemd unit and Caddyfile inline (no checkout needed), folding in the
      `deploy/install-service.sh` and `deploy/caddy-setup.sh` logic; keep the hardened
      `deploy/abyssum-web.service` and `deploy/Caddyfile.example` as references in sync.
- [x] Apply exposure to the app bind; enforce a CIDR restriction via the proxy `remote_ip`
      allow-list (or a firewall rule when no proxy); keep the app on localhost when the
      proxy is selected.
- [x] Add an uninstaller (`uninstall.sh` and/or `install.sh --uninstall`): remove binaries +
      created service + generated proxy config; preserve data by default; `--purge` to
      remove data; `--yes` for unattended.
- [x] Rewrite the README install/deploy sections and `docs/deploy/` so no step assumes a
      source checkout; document the wizard, the flags, and the uninstaller.
- [x] Lint `install.sh` and the uninstaller with shellcheck in the release workflow; extend
      `tests/install.test.sh` to cover the flag paths and an `--uninstall --yes` round-trip.
      (Offline suite covers the binary install/verify paths and a user-scope uninstall
      round-trip; the service/proxy paths need a real host — see below.)
- [x] Verify: a single piped command with flags stands up binaries + service + TLS proxy on
      a host with no checkout; the uninstaller cleanly reverses it.
