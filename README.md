# Abyssum

A patient, stealthy **API vulnerability scanner for authorized security testing** —
bug-bounty and pentest work you have permission to do. It discovers and probes REST and
OpenAPI surfaces, CORS, broken access control, IDOR, and GraphQL, with a CLI and a web UI
sharing one engine.

Its defining trait is restraint: out of the box Abyssum paces itself with randomized,
non-zero delays, backs off when a host shows distress, and presents realistic rotating
User-Agents — so a default scan should not DoS the target or trip a basic IDS/IPS.
Aggression is opt-in.

> ⚠️ **Authorized use only.** Point Abyssum only at systems you own or are explicitly
> permitted to test. You are responsible for staying within scope and the law.

## Install

One line, no dependencies to install, no toolchain — it downloads static binaries and
verifies their SHA-256 checksums before putting anything on your PATH:

```sh
curl -fsSL https://raw.githubusercontent.com/IndustriousKraken/Abyssum/master/install.sh | bash
```

This installs `abyssum` (CLI) and `abyssum-web` (web UI) to `/usr/local/bin`, or to
`~/.local/bin` when run as non-root. **Run in a terminal, it then offers an optional guided
setup** — run `abyssum-web` as a service, choose how it's exposed, and set up an HTTPS
reverse proxy. Piped with no terminal (CI, cron), it installs the binaries and stops there.

Options (pass through `curl … | bash -s --`):

- `--user` — install into `~/.local/bin`
- `--version <tag>` — install a specific release instead of the latest
- `--service` — run `abyssum-web` as a systemd service (Linux)
- `--expose localhost|all|<ip>` — how the web UI binds (default `localhost`)
- `--allow-cidr <cidr>` — restrict network access to a CIDR (applied by the proxy)
- `--proxy` `--site <host>` — set up a Caddy HTTPS reverse proxy (internal, self-signed CA)
- `--yes` / `--no-wizard` — accept defaults / never prompt

A full one-shot setup behind HTTPS, unattended:

```sh
curl -fsSL …/install.sh | bash -s -- --service --proxy --site abyssum.lab --yes
```

The installer needs only `curl` and `sha256sum` (or `shasum`); service/proxy setup is
Linux/systemd (and needs `caddy` for the proxy). Supported targets: Linux x86_64/aarch64,
macOS aarch64. Deployment details — CA trust, DNS, hardening — are in
[`docs/deploy/CADDY.md`](docs/deploy/CADDY.md).

### Uninstall

```sh
curl -fsSL https://raw.githubusercontent.com/IndustriousKraken/Abyssum/master/uninstall.sh | bash -s -- --yes
```

Removes the binaries, the service, and any proxy config the installer generated. Your data
is kept unless you add `--purge`.

### From source

Requires a Rust toolchain.

```sh
cargo build --release      # binaries land in target/release/{abyssum,abyssum-web}
cargo test                 # run the suite
```

## Quickstart

Run one or more scanners against one or more targets. Both flags are repeatable; a bare
host is treated as `https`:

```sh
abyssum --targets api.example.com \
        --scanners rest_discovery --scanners openapi_discovery
```

### Scanners

| id                  | Looks for |
|---------------------|-----------|
| `rest_discovery`    | Reachable REST endpoints via wordlist discovery + classification |
| `openapi_discovery` | Exposed OpenAPI/Swagger documents |
| `cors`              | Permissive / reflected CORS origins, credentialed exposure |
| `bac`               | Broken access control — sensitive endpoints reachable unauthenticated |
| `idor`              | Insecure direct object references (object-id enumeration) |
| `graphql`           | Introspection exposure, unbounded query depth, query batching |

### Authenticated scans

Most real targets need a session. Supply a cookie and/or a bearer token; either, both, or
neither:

```sh
abyssum --targets api.example.com --scanners idor --scanners bac \
        --cookie 'session=abc123' \
        --bearer eyJhbGciOi...
```

> Note: values passed on the command line are visible to other local users (process table)
> and saved in shell history — avoid it on shared hosts.

### Auth-differential scans

Give **two or more** named identities to run the surface as each and report where access
diverges — the ground where horizontal (user-A sees user-B) and vertical (anon reaches a
privileged route) access-control bugs live. Form: `label[:cookie=VALUE][:bearer=TOKEN]`; a
bare label is the anonymous identity.

```sh
abyssum --targets api.example.com --scanners rest_discovery \
        --identity alice:bearer=tok-a \
        --identity bob:cookie=session=b \
        --identity guest
```

### Output and reports

Findings render as a table by default; `--output json|csv` for machine-readable output.
Every scan is persisted, so you can render a report later by session id:

```sh
abyssum --targets api.example.com --scanners cors --output json

abyssum report <session-id> --format markdown          # or json | csv | hackerone
abyssum report <session-id> --format hackerone --output report.md --no-evidence
```

### Pacing

Pacing overrides for a single run (they never lower the configured floor):

```sh
abyssum --targets api.example.com --scanners rest_discovery \
        --min-delay 2 --max-delay 6
```

## Web UI

```sh
abyssum-web                      # serves on http://127.0.0.1:8000 by default
```

The web surface is authenticated (register the first account, which is bootstrapped as
admin), and shows live scan progress over a WebSocket. Change the bind address in config.

## Deployment (service + HTTPS)

`abyssum-web` binds `127.0.0.1` by default — safe, but localhost-only, which makes its
multi-user accounts pointless unless everyone shares one keyboard. The supported way to
give a team access is to keep the app on localhost and put a **TLS reverse proxy** in
front; `abyssum-web` speaks plain HTTP on purpose and leaves TLS to the proxy.

The installer does both — run it in a terminal and accept the prompts, or one-shot it:

```sh
curl -fsSL …/install.sh | bash -s -- --service --proxy --site abyssum.lab --yes
```

That runs `abyssum-web` as a systemd service on `127.0.0.1` and stands up a [Caddy](https://caddyserver.com)
reverse proxy with an internal (self-signed) CA — ideal for a LAN or VPN with no public DNS.
Trust Caddy's root CA on each client to avoid browser warnings. To expose the app directly
instead (trusted networks only — plain HTTP), use `--expose all` or `--expose <ip>`, or
`--allow-cidr` to limit access to a range.

The full walkthrough — CA trust for other machines, DNS/hosts, systemd hardening, and the
reference `deploy/` files — is in [`docs/deploy/CADDY.md`](docs/deploy/CADDY.md).

## Configuration

Configuration layers in strict precedence: **built-in defaults → YAML file →
`ABYSSUM_*` environment variables** (each later source wins). Both binaries read the
config from a fixed, working-directory-independent location by default, so a
PATH-installed binary behaves the same wherever you run it:

- **Config**: `$XDG_CONFIG_HOME/abyssum/abyssum.yaml` (i.e.
  `~/.config/abyssum/abyssum.yaml`). Override with `--config <path>` or `ABYSSUM_CONFIG`.
- **Database**: `$XDG_DATA_HOME/abyssum/abyssum.db` (i.e.
  `~/.local/share/abyssum/abyssum.db`). Because both binaries resolve it from this one
  shared default, CLI scans show up in the web dashboard with zero configuration.
  Override with `ABYSSUM_DATABASE_PATH` or the YAML `database.path`.

Parent directories are created on first use. A missing config file is fine (defaults
apply); a malformed file is a hard error. Upgrading from an older build that used a
CWD-relative `data/abyssum.db`? Move that file to the new location (or point
`ABYSSUM_DATABASE_PATH` at it) to keep your existing sessions and admin account.

A full `abyssum.yaml` with the defaults:

```yaml
server:
  host: 127.0.0.1
  port: 8000
  allow_private_custom_targets: false   # web custom-requests tool may hit private/reserved IPs

database:
  path: /home/user/.local/share/abyssum/abyssum.db   # omit to use $XDG_DATA_HOME/abyssum/abyssum.db (~ is NOT expanded in YAML)

scanning:
  min_delay: 1.0                # hard floor on inter-request delay (seconds); adaptive logic only slows past it
  max_delay: 3.0               # upper bound of the randomized delay window
  max_concurrency: 4
  user_agent_rotation: per-request   # per-request | per-scan
  subdomain_bruteforce: false        # opt-in active DNS brute-force in subdomain recon (louder; off by default)

log:
  level: info                  # e.g. debug, or a directive like abyssum_core=debug,info

auth:
  session_absolute_max_hours: 24
  session_idle_timeout_minutes: 60

ai:                            # outbound "analyze finding" assist (OpenAI-compatible)
  base_url: http://localhost:11434/v1
  model: llama3.1
  enabled: true
  timeout_seconds: 30
  temperature: 0.2
  max_evidence_chars: 4000
  # api_key: sk-...            # optional; keyless endpoints (e.g. Ollama) are supported
```

### Environment overrides

Every setting has an `ABYSSUM_*` override, e.g. `ABYSSUM_SERVER_PORT`,
`ABYSSUM_SCANNING_MIN_DELAY`, `ABYSSUM_DATABASE_PATH`, `ABYSSUM_LOG=debug`. The AI provider
uses a double-underscore form so a key need never be written to disk:

```sh
export ABYSSUM_AI__API_KEY=sk-...
export ABYSSUM_AI__MODEL=gpt-4o-mini
```

## Architecture

A Cargo workspace: a surface-agnostic core engine with thin surfaces over it.

- `abyssum-core` — config, rate limiter, scan orchestration, persistence (SQLite), seed data
- `abyssum-scanners` — the individual scanners, registered into the engine
- `abyssum-cli` — the `abyssum` binary
- `abyssum-web` — the `abyssum-web` binary (axum + HTMX/Alpine)

All outbound HTTP flows through one paced path, so the delay floor and User-Agent rotation
cannot be bypassed. Design intent and the binding stealth philosophy live in
`openspec/project.md`; deferred ideas live in `roadmap/`.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
