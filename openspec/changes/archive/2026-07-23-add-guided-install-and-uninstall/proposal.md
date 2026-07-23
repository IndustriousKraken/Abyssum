# One installer with guided setup, plus an uninstaller

## Why

The install story has drifted badly. What should be a one-line install now takes three
separate scripts (`install.sh` for binaries, `caddy-setup.sh`, `install-service.sh`),
hand-edited systemd units, and docs that tell you to run commands as if you had cloned the
repo — which the normal `curl … | bash` user never did. There is also no way to remove an
install. Nobody will jump through those hoops; "easy to install and configure" is the bar,
and this misses it.

Consolidate to **one installer with an optional guided setup** and a matching
**uninstaller**, without breaking the plain one-line install.

## What Changes

- When there is no controlling terminal and no flags (CI, cron, piped-into-a-pipeline),
  the installer installs the verified binaries and nothing else — the non-interactive
  one-liner is unchanged. An interactive run (including `curl … | bash` from a real
  terminal, which still has a controlling terminal via `/dev/tty`) additionally offers
  the guided setup below.
- When a terminal is available (including `curl … | bash` from a real terminal), the
  installer offers a **guided setup**: run as a service? how should the web UI be exposed
  (localhost only / all interfaces / a specific address, optionally restricted to a CIDR)?
  set up a TLS reverse proxy? Each prompt has a safe default and can be declined.
- Every choice has a **flag** so a scripted/piped install can do the whole thing
  unattended (`--service`, `--expose`, `--allow-cidr`, `--proxy`, `--site`, `--yes`, …).
- Setup is **self-contained**: the installer generates the systemd unit and reverse-proxy
  config itself — no checkout required. The logic in today's `deploy/caddy-setup.sh` and
  `deploy/install-service.sh` folds into the installer (or they become thin wrappers).
- A new **uninstaller** (a script and/or `install.sh --uninstall`) removes the binaries
  and whatever setup the installer created (service, generated proxy config), keeps user
  data by default with an option to purge it, and runs unattended with `--yes`.
- The README and deploy docs are rewritten so **no step assumes a source checkout**.

## Out of scope

- Changing the release/build pipeline, checksums, or platform matrix (unchanged).
- Managing the operator's DNS.
