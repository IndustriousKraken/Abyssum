# Changelog

All notable changes to Abyssum are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.3] - 2026-07-21

### Fixes

- Serves `/static/*` from installed `abyssum-web` binaries — CSS, HTMX, and
  Alpine now load, so page styling and the live dashboard fragments (stats,
  sessions, findings, progress) work from a release install and not only a
  source checkout.

### Also included

- The installer now packs the web static directory, and an example Caddy
  reverse-proxy configuration is provided.

## [1.0.2] - 2026-07-20

**Deep surface mapping** — find the attack surface before scanning it:

- Adds passive subdomain discovery with subdomain-takeover detection.
- Adds opt-in active subdomain brute-forcing for hosts absent from public sources.
- Adds origin-IP discovery to reach a host hidden behind a CDN/WAF.
- Adds ASN and netblock enumeration to expand from one host to the
  organization's real external footprint.
- Adds cloud asset discovery for exposed object-storage buckets and stale
  cloud endpoints.

**Observing proxy** — a non-intercepting proxy that watches and records:

- Adds the observing-proxy core that records API traffic without ever pausing
  the operator on a breakpoint.
- Scores captured exchanges by security interest and auto-flags tokens, IDs,
  and error-leaking responses into a triage view.
- Exports captured traffic to Burp/Postman, an OpenAPI spec, or an external
  tool or AI agent.

## [1.0.1] - 2026-07-16

- Moves the workspace to the Rust 2024 edition.
- Fixes the release cross-compilation workflow (Zig 0.14).

## [1.0.0] - 2026-07-16

First release of the pure-Rust v2 rebuild: a stealth-first API vulnerability
scanner for authorized bug-bounty and security testing, with a CLI and a web UI
sharing one engine.

- **Six API vulnerability scanners** — REST endpoint discovery, OpenAPI/Swagger
  discovery, CORS misconfiguration, Broken Access Control (BAC), IDOR, and
  GraphQL (introspection, query nesting, batching, and sensitive-data disclosure).
- **CLI and web UI on one engine** — the `abyssum` CLI for automation/CI and an
  HTMX/Alpine web UI with live WebSocket progress and mid-scan cancellation,
  both behind multi-user authentication with per-user scan ownership.
- **Stealth-first by default** — every outbound request routes through a single
  rate-limiting authority with conservative randomized pacing, a hard delay
  floor, distress-aware backoff, and rotating User-Agents, so a default scan
  will not DoS the target or trip a basic IDS/IPS.
- **Authenticated and differential access-control testing** — pass bearer/cookie
  credentials to CLI scans, and run the same surface under multiple named
  identities to report where access diverges.
- **Triage-ready findings** — durable scan and finding history, duplicate
  collapsing with importance ranking, run-to-run diffs, freeform notes with
  color-coded tags, and Markdown/JSON/CSV/HackerOne report exports.

### Also included

- AI-assisted finding triage through an outbound, OpenAI-compatible endpoint
  (keyless endpoints supported).
- A custom single-request tool (any method, headers, and body) shared by the
  CLI and web surfaces.
- Curated per-scanner wordlists and a realistic User-Agent pool, seeded into the
  database on first run.
- Distribution as cross-compiled static `abyssum` and `abyssum-web` binaries,
  installable with a single-command `install.sh`.
