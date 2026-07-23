# Design

## One network face

The web surface always binds `127.0.0.1`. The reverse proxy is the only thing that faces the
network, so every "who can reach this" question is a **proxy** question. That removes the
contradictory state entirely — there is no combination in which the app is both behind a
proxy and bound to a network interface.

## Proxy reach → Caddy directives

The three reach choices map directly onto Caddy:

- **All addresses** (default) — the ordinary `https://<site> { … }` block; Caddy binds `:443`
  on every interface. This is what a LAN/VPN box wants.
- **Loopback only** — add `bind 127.0.0.1` inside the site block. Useful when the operator
  reaches the box over an SSH tunnel and wants nothing on the wire at all.
- **Restricted to a CIDR** — `@allowed remote_ip <cidr>` guarding the `reverse_proxy`, with a
  `403` otherwise. Composes with either bind choice.

## Wizard flow

`service? → proxy? → (if proxy) site, reach, optional CIDR`. There is no app-bind question,
so the operator is never asked something the installer will override. When the proxy is
declined, the app is host-only and the installer says so plainly rather than offering to
expose it.

## The escape hatch stays, but off the friendly path

An operator who genuinely needs a direct bind (a container, or a proxy on a different host)
sets `ABYSSUM_SERVER_HOST` themselves. The installer neither asks about it nor sets it, so the
insecure-by-omission path requires a deliberate act outside the guided flow.
