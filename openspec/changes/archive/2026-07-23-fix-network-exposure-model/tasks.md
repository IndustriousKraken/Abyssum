# Tasks

- [x] Remove the app-level exposure choice from `install.sh`: drop the `--expose` flag and the
      wizard's bind prompt; the installer never sets `ABYSSUM_SERVER_HOST`.
- [x] Add proxy-reach selection: `--proxy-bind all|loopback` (default `all`), keeping
      `--allow-cidr <cidr>`; both are rendered into the generated Caddyfile
      (`bind 127.0.0.1` for loopback; `@allowed remote_ip <cidr>` + `403` for the CIDR).
- [x] Reorder/reword the wizard to `service? → proxy? → (if proxy) site, reach, optional CIDR`,
      with no app-bind question; when the proxy is declined, state plainly that the web UI is
      reachable only from this host.
- [x] Ensure the generated systemd unit leaves the bind at the loopback default (no
      `ABYSSUM_SERVER_HOST` line).
- [x] Update the README and `docs/deploy/` to describe proxy reach rather than app exposure,
      and to state that the app is always on loopback.
- [x] Update `tests/install.test.sh` for the new flags; assert the installer never emits an
      `ABYSSUM_SERVER_HOST` bind into the generated unit. (Source-level guard — the unit is
      only generated with root/systemd, so the assertion checks the installer itself.)
- [x] Verify on a real host: `--proxy --proxy-bind all` is reachable from the LAN over HTTPS;
      `--allow-cidr` refuses a client outside the range; without `--proxy` the UI answers only
      on the host itself. Verified end-to-end on a Linux/systemd host with caddy:
      `https://192.168.4.3/` → 303 through the proxy while `http://192.168.4.3:8000/` was
      refused (app loopback-only); service unit carried no `ABYSSUM_SERVER_HOST`; the
      `@allowed remote_ip` matcher admitted an in-range client (303) and refused an
      out-of-range one (403) — the CIDR case exercised via the generated config on an
      unprivileged port, since writing `/etc/caddy` on `:443` needs root.
