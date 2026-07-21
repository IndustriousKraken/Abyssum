# Serving abyssum-web over the network (Caddy + internal TLS)

`abyssum-web` binds `127.0.0.1` by default. That is the safe default, but it makes
the app's multi-user accounts useless unless everyone shares one keyboard — so a
real deployment needs a network path. The supported one is a **TLS reverse proxy**:
keep `abyssum-web` on localhost and let the proxy face the network. `abyssum-web`
speaks plain HTTP on purpose and leaves TLS to the proxy (a standard axum pattern —
the app doesn't reimplement certificate handling).

This guide uses [Caddy](https://caddyserver.com) with its **internal CA** (a
self-signed root), which is ideal for a LAN or VPN with no public DNS.

```
   client ──HTTPS :443──▶  Caddy  ──HTTP──▶  abyssum-web (127.0.0.1:8000)
                            (TLS)             (localhost only)
```

Only Caddy is reachable from the network; the app is never on a routable interface.

## Quick start

On the server that runs `abyssum-web`:

```sh
# 1. Install Caddy (Debian/Ubuntu shown; see caddyserver.com/docs/install for others)
sudo apt install -y caddy

# 2. Generate + validate a Caddyfile for your hostname or IP
deploy/caddy-setup.sh --site abyssum.lab        # omit --site to use this box's IP

# 3. Put it in place and (re)load Caddy
sudo cp Caddyfile /etc/caddy/Caddyfile
sudo systemctl reload caddy

# 4. Trust Caddy's internal CA on this host so browsers don't warn
sudo caddy trust
```

Then browse `https://abyssum.lab/`. `deploy/caddy-setup.sh --run` will also just run
Caddy in the foreground if you'd rather not use systemd. The generated config matches
[`deploy/Caddyfile.example`](../../deploy/Caddyfile.example), which you can copy and
edit by hand instead.

## Trusting the internal CA on other machines

`caddy trust` only trusts the CA on the machine it runs on. Every *other* client that
connects needs Caddy's root certificate imported, or it will show a certificate
warning. Export the root once from the server:

```sh
# Location varies by install; for the systemd 'caddy' service it's typically:
sudo cp /var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt abyssum-root.crt
# (running as your own user, it's ~/.local/share/caddy/pki/authorities/local/root.crt)
```

Then import `abyssum-root.crt` on each client:

- **Linux:** copy to `/usr/local/share/ca-certificates/abyssum-root.crt`, then
  `sudo update-ca-certificates`. Firefox uses its own store — import via
  Settings → Privacy & Security → Certificates → View Certificates → Authorities.
- **macOS:** open in Keychain Access → System → set "Always Trust".
- **Windows:** import into "Trusted Root Certification Authorities" (Local Machine).

For a small trusted lab you can skip all this and just accept the browser warning —
the connection is still encrypted; the warning is only about the CA not being
pre-trusted.

## Name resolution

Clients must be able to reach the address in the Caddyfile:

- **Hostname** (e.g. `abyssum.lab`) — add a record to your VPN/lab DNS, or an
  `/etc/hosts` line on each client: `10.42.12.184  abyssum.lab`.
- **Bare IP** (e.g. `10.42.12.184`) — no DNS needed; Caddy issues the internal cert
  with the IP as a SAN. Pass it as `--site 10.42.12.184`.

## Running Caddy

- **systemd (recommended):** the official Caddy package ships a `caddy` service that
  already has permission to bind `:443`. Put the file at `/etc/caddy/Caddyfile` and
  `sudo systemctl reload caddy`. Logs: `journalctl -u caddy -f`.
- **Foreground / manual:** `sudo caddy run --config Caddyfile` (root or the
  `cap_net_bind_service` capability is required to bind `:443`).

## Keep abyssum-web on localhost

Leave `server.host` at its default `127.0.0.1` (do **not** set
`ABYSSUM_SERVER_HOST=0.0.0.0` when running behind Caddy). Caddy connects to it over
loopback; binding the app to `0.0.0.0` as well would re-expose the plain-HTTP port on
the network, defeating the point.

## Security notes

- Even with TLS, keep the listener on a trusted network (your VPN). The internal CA
  authenticates the server to clients; it is not a substitute for network access
  control.
- `abyssum-web` sets its own CSP, HSTS, `X-Frame-Options: DENY`, and
  `X-Content-Type-Options: nosniff`, so the Caddyfile only needs to terminate TLS and
  strip its own `Server` header.
- Rotate/limit accounts as usual — the first registered account becomes the admin.
