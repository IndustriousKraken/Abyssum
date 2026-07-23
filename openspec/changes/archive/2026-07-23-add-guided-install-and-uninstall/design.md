# Design

## Preserve the one-liner; add a wizard on top

Detect a controlling terminal (`[ -t 0 ]`, else try `/dev/tty`). With a terminal and no
`--no-wizard`, run the guided setup after installing binaries — this is what makes even
`curl … | bash` from a real terminal interactive (the prompts read from `/dev/tty`, the
rustup pattern). With no terminal and no setup flags (CI, piped-into-cron), behave exactly
as today: install binaries, exit. Any setup flag implies non-interactive setup.

## Self-contained setup (no checkout)

The installer must configure a host that only ever ran `curl … | bash`, so it generates the
artifacts inline rather than reading repo files:

- **Service**: write `/etc/systemd/system/abyssum-web.service` from a here-doc, substituting
  the run-as user, the installed binary path, `ProtectHome` (read-only if the binary is
  under `/home`), the DB path (`/var/lib/abyssum` via `StateDirectory`), and the bind. Then
  `daemon-reload` + `enable --now`. This is the current `deploy/install-service.sh` logic,
  folded in; the hardened `deploy/abyssum-web.service` stays as the readable reference and
  the source the here-doc is kept in sync with.
- **Reverse proxy**: write a Caddyfile with `tls internal` (self-signed CA for a LAN/VPN),
  `reverse_proxy 127.0.0.1:8000`, install it, and reload Caddy — the current
  `deploy/caddy-setup.sh` logic. If `caddy` is absent, print the one install command rather
  than silently pulling a package.

## Exposure + CIDR

The exposure choice maps to the app's bind and, optionally, an access allow-list:

- **localhost only** → `ABYSSUM_SERVER_HOST=127.0.0.1` (the default; pair with the proxy for
  network access).
- **all interfaces** → `0.0.0.0`. **specific address** → that interface IP.
- **restrict to a CIDR** → an allow-list, not a socket bind (a socket can't bind a CIDR).
  Enforced by the reverse proxy's `remote_ip` matcher when the proxy is chosen; otherwise
  offer a host firewall rule (ufw/nftables). Choosing the proxy is recommended for any
  exposed bind, since it also adds TLS.

## Uninstaller

`uninstall.sh` (curl-able) and `install.sh --uninstall` share one routine: stop/disable/rm
the service unit, remove the generated Caddy config (leave a hand-written `/etc/caddy`
alone), remove the binaries from wherever they were installed. **Keep data by default**
(`/var/lib/abyssum`, `~/.config/abyssum`); `--purge` removes it. `--yes` skips the y/N
prompt so it runs as a one-liner — useful for real uninstalls and for testing that the
installer is actually easy (clean-slate between runs). Mirrors the safe-by-default
uninstaller in the operator's other projects.

## CI

Lint `install.sh` **and** the uninstaller with shellcheck in the release workflow (extends
the existing installer-lint gate). Extend `tests/install.test.sh` to exercise the
non-interactive flag paths and a `--uninstall --yes` round-trip.
