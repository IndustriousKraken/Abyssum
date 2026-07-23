# Fix the network-exposure model: the app stays on loopback, the proxy has the reach

## Why

The installer currently offers an **app-level** exposure choice — "localhost / all
interfaces / a specific address" — and canon now blesses it. That contradicts the design
the whole deployment story is built on: the web surface stays on loopback and a TLS reverse
proxy is the network face. It also produced a combination that cannot be true — choosing
"all interfaces" *and* a reverse proxy — which the installer silently resolved by ignoring
the operator's answer.

It came from a misreading. The requirement was always about **what the proxy serves to**
(all addresses, loopback only, or a restricted CIDR), not about binding the app itself to a
network interface. The app was never supposed to leave loopback.

Canon also never pinned the loopback default at all: no specification mentions the bind
host, so the security property the deployment story depends on exists only in `config.rs`.
The escape hatch is specified; the safe default is not. This change inverts that back.

## What Changes

- **Pin the safe default in canon**: the web surface binds loopback by default, network
  access is provided by a reverse proxy in front of it, and automated setup never configures
  a non-loopback bind.
- **Remove the app-level exposure choice** from the wizard and from the flags. The installer
  no longer asks how to bind the app, and no flag binds it to a network address.
- **Replace it with proxy reach**: when the reverse proxy is selected, the operator chooses
  which addresses the proxy serves on (all addresses, or loopback only) and may restrict
  access to a CIDR. Both are enforced at the proxy.
- Without a proxy, the web surface is reachable only from the host itself — which is the
  point of the default, not a limitation to work around.

## Out of scope

The low-level `server.host` / `ABYSSUM_SERVER_HOST` setting stays as-is for advanced and
containerized deployments (inside a container the container boundary is the isolation, and a
reverse proxy may live on another host). This change only stops the **installer** from
setting it and pins the default it departs from.
