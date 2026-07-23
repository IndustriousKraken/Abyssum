# Report the shared trust-store CA on uninstall instead of removing it

## Why

Setting up the reverse proxy installs Caddy's local root certificate authority into the
host's system trust store (`caddy trust`). The uninstaller removes the service, the
binaries, and the generated proxy configuration — but leaves that CA behind. Canon says the
uninstaller removes "any host setup the installer created," so today's behavior silently
falls short of its own contract.

The obvious fix is wrong, though: Caddy's local CA is **shared by every `tls internal` site
on the host**. Running `caddy untrust` from Abyssum's uninstaller would break the
certificates of unrelated Caddy services on the same machine. An uninstaller causing
collateral damage to other software is worse than the leftover.

So the CA is deliberately **reported, not removed** — and that carve-out belongs in the
spec, so the behavior is intentional rather than an unspoken omission.

## What Changes

- The uninstaller, when it removes an abyssum-managed reverse-proxy configuration, SHALL
  report that the proxy's locally-trusted CA remains in the system trust store and how to
  remove it (`caddy untrust`), and SHALL NOT remove it itself.
- The spec's `Uninstaller` requirement is amended to carve out host state that is shared
  with other software: it is reported rather than removed.
- The installer stops trusting the CA silently — it announces that it added a certificate
  authority to the host's trust store, so the operator knows the uninstall notice refers to
  something real.

## Out of scope

An opt-in `--untrust-ca` flag. Typing `caddy untrust` is a one-liner, and leaving the
decision entirely with the operator avoids encoding a guess about what else uses Caddy.
