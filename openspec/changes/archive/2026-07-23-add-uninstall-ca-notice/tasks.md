# Tasks

- [x] `uninstall.sh`: when an abyssum-managed Caddy config is removed, print a notice that
      Caddy's local root CA is still in the system trust store, that it may be shared with
      other `tls internal` sites, and that `sudo caddy untrust` removes it.
- [x] `uninstall.sh`: do NOT run `caddy untrust` itself.
- [x] `install.sh`: announce that `caddy trust` added a certificate authority to the host's
      trust store instead of doing it silently (drop the blanket output suppression so a
      failure is visible too).
- [x] Update the README / `docs/deploy/CADDY.md` uninstall notes to mention the CA is left
      in place and how to remove it.
- [x] Add a regression guard in `tests/install.test.sh`: the uninstaller must mention
      `caddy untrust` but must never execute it.
- [x] Verify on a real host: after `--proxy` setup then uninstall, the notice appears, the CA
      is still trusted, and `caddy untrust` removes it. Verified end-to-end on a
      Linux/systemd host: install announced the trust-store change and
      `Caddy_Local_Authority_-_2026_ECC_Root_*.crt` appeared in
      `/usr/local/share/ca-certificates/`; uninstall printed the notice and left the CA in
      place; `sudo caddy untrust` then removed it ("certificate uninstalled properly from
      linux trusts").
