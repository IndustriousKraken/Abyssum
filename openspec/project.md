# Abyssum — Project Context

> This is the **canon**: the de-conflicted source of intent for the pure-Rust v2 rebuild.
> Specs (`openspec/specs/`) describe behavior; this file holds product intent, locked
> technical decisions, and explicit non-goals. When a change proposal conflicts with this
> file, this file wins — update it deliberately, don't drift from it.

## Product Intent

Abyssum is an **API vulnerability scanner for bug bounty hunters and security
researchers** operating **within authorized scope** (published bug bounty programs,
signed pentest engagements, or their own systems).

The core value proposition sits at the intersection of **thoroughness** and **stealth**:

- **Thoroughness** — a suite of scanners covering REST endpoint discovery, OpenAPI/Swagger
  exposure, CORS misconfiguration, Broken Access Control (BAC), IDOR, and GraphQL.
- **Stealth / good citizenship** — randomized request pacing and per-domain adaptive
  backoff so testing does not trip rate limits, WAFs, or lockouts. The user's configured
  delay is a **floor**; adaptive logic may only ever *slow down*, never speed up past it.

It ships as a **single self-contained binary** (no Python runtime, no interpreter), usable
two ways that share one engine: a **CLI** for automation/CI and a **web UI** for
interactive use with live scan progress and persistent history.

## Who it's for

Bug bounty hunters, pentesters with authorization, security researchers, and internal
security teams assessing their own applications. Single operator or a small team sharing
one instance.

## Positioning & Identity

Abyssum deliberately does **not** compete with the fast, loud, template-driven scanners
(Nuclei and friends) that excel at grabbing the first obvious finding on a freshly-shipped
site. That territory is well served. Abyssum is the **slow, deep, thorough** tool you reach
for when the blatant bugs are already gone: it runs unattended over long horizons, stays
under the radar, and surfaces the *occult* findings — forgotten infrastructure, the
non-obvious API flaw, the misconfiguration nobody scanned patiently enough to reach. It finds
the obvious things too; it just isn't *for* them.

A consequence worth stating plainly: **depth must come from detection, not just politeness.**
Pacing, UA rotation, and patience buy *access and endurance* — they don't, by themselves, find
a subtle bug. The differentiating depth lives in capabilities like the observing proxy,
cross-endpoint / stateful reasoning, auth-differential testing, and change-detection for
unattended runs (see `future-capabilities.md`). v1 establishes the **posture and platform**;
later work delivers the **depth**. Hold both honestly.

**Identity.** *Abyssum* is the accusative — "into the deep" — the threshold from the visible
surface down into the depths where the hidden things live. Tagline: **"the deep calleth unto
the deep"** (with the Latin *abyssus abyssum invocat* as a secondary mark). A long unattended
run is a **descent**.

**Claims discipline.** The stealth claim is scoped to **basic** IDS/IPS — never
"undetectable." Any claim about evading advanced or behavioral defenders must be a **specific,
reproducible case report** (the environment, what was found, and *why* it slipped through),
never a blanket marketing assertion.

## Design Philosophy — Stealth & Infrastructure Respect

This is Abyssum's defining stance, and it is **binding on every capability**: testing should
be effective without being destructive or conspicuous. What sets Abyssum apart from louder
scanners is that **its default configuration will not DoS the target and will not trip a
basic IDS/IPS.** Aggression is strictly opt-in, never the default.

Concretely, the specs must uphold:

- **Conservative by default.** Out of the box, pacing delays are non-zero and randomized,
  concurrency is bounded, and timeouts are sane. A user must *deliberately* turn the dials up
  to scan aggressively.
- **The user's pacing is a hard floor.** Adaptive logic may only ever slow down, never below
  the configured minimum delay. (See `rate-limiting`.)
- **Randomized, non-patterned timing.** Each request is spaced by a delay drawn at random so
  traffic forms no fixed cadence for signature-based detection to key on.
- **Blend in, don't announce.** Outbound requests present realistic browser/mobile
  User-Agents from a rotating pool by default — never a "Abyssum / Security Scanner" banner
  that an IDS flags on sight. (See `seed-data`.)
- **Back off when the target hurts.** Rate-limit signals (429/403) *and* signs of server
  distress (a surge of 5xx / elevated error rate) increase backoff; sustained distress is a
  stop condition, not something to push through. (See `rate-limiting`.)
- **Reconnaissance, not exploitation.** Scanners probe to *detect* misconfigurations; they do
  not weaponize them, access third-party data, or modify state.

These are editable in *degree* — the exact delays, thresholds, and UA pool are all tunable —
but the *principle* of safe, quiet defaults is the project's identity and must not be
defaulted away.

## Locked Decisions (v2 canon)

These resolve contradictions found in the v1 (Python) docs. They are settled; changes
must conform.

| Area | Decision |
|------|----------|
| **Language** | Pure Rust. No Python anywhere. **No `pyo3`** — the v1 experimental branch's pyo3 bridge is discarded. |
| **Distribution** | Cross-compiled static binaries (`abyssum`, `abyssum-web`) attached to GitHub Releases, installed via a thin `install.sh` (download → verify SHA-256 → place on PATH). Pattern mirrors the `octopus-autocoder` release pipeline. |
| **Async runtime** | Tokio. |
| **HTTP client** | `reqwest`. |
| **Web framework** | `axum`. |
| **Frontend** | **HTMX + Alpine.js**, server-rendered HTML fragments. Live scan progress via WebSocket. No SPA, no React/Vue, no build step for the frontend. |
| **Persistence** | SQLite via `sqlx`. **No Redis, no Postgres/AsyncPG** in v1 (those were aspirational config bloat in v1 — explicitly out). |
| **Multi-user + auth** | The instance is **multi-user with authentication**. Local accounts, hashed passwords, server-side sessions. Scan sessions are owned by the creating user; an `admin` role may view all. (Teams/sharing/SSO are deferred.) |
| **AI integration (direction)** | **Outbound only in v1**: Abyssum calls an **OpenAI-compatible** chat API for AI-assisted analysis of findings. Provider is configurable (base URL + model). **The API key is optional/absent-friendly** so a self-hosted endpoint (e.g. Ollama exposed as an OpenAI-compatible API) works with no key. AI is **analysis-only** (it never takes actions); the keyless/self-hosted option also sidesteps hosted-model refusals on legitimate authorized analysis. |
| **CLI/Web parity** | Both surfaces call one shared `core` crate. Parity is structural (same engine), not enforced by drift-detection tests as in v1. |
| **Reference data** | Curated wordlists (per scanner) and the User-Agent pool ship as bundled assets (`assets/seed/`) embedded in the binary and **seeded into the database on first run** (idempotent), then read at runtime. Default UA rotation uses realistic browser/mobile identities only. (See `seed-data`.) |
| **License** | Dual-licensed **MIT OR Apache-2.0** (Rust ecosystem convention); crates declare `license = "MIT OR Apache-2.0"`. License texts live at repo root (`LICENSE-MIT`, `LICENSE-APACHE`). |

## Architecture (shape, not spec)

A Cargo workspace with a shared core so CLI and web cannot diverge:

```
abyssum-core      # config, error model, logging, scan orchestration, rate limiter,
                  # persistence, auth, the BaseScanner trait + scanner registry
abyssum-scanners  # the six scanners, each implementing the core trait
abyssum-web       # axum server, HTMX/Alpine templates, websocket progress  -> binary `abyssum-web`
abyssum-cli       # clap CLI, table/json/csv output                         -> binary `abyssum`
```

Everything observable (scan behavior, persistence, auth, output) is specified in
`openspec/specs/`. Crate names, libraries, and internal structure live here and in each
change's `design.md` — **never** in `spec.md`.

**One engine, many surfaces (architecture principle).** Abyssum is fundamentally a *patient,
stealthy, persistent engine* that observes and probes a target environment over long horizons,
stores everything, and surfaces the non-obvious through correlation. The *environment* —
external API / perimeter (v1), and later others — is a **surface adapter** on that engine, not
the engine itself. Therefore `abyssum-core` MUST stay **surface-agnostic**: it must not assume
the only target is an HTTP API. Every future capability classifies as exactly one of three
kinds — a new **surface** (where we point the engine), a new **detection/correlation** (what we
infer from collected data), or a new **evasion/transport** (how we stay quiet and move data).
This taxonomy is both the architecture and the filter for the idea backlog. Keeping `core`
clean of surface-specific assumptions is cheap now and brutal to retrofit later.

## Non-Goals for v1 (explicitly deferred)

Documented in v1 but **out of scope** for the rebuild, to keep the canon tight and the
build bounded. Each can return later as its own OpenSpec change:

- Proxy / traffic-observer module
- IP rotation / multi-cloud egress
- Distributed testing "personas" and multi-instance orchestration
- **Inbound** API for external AI agents to drive Abyssum (v1 AI is outbound only)
- Webhooks and batch/bulk external API operations
- User-uploaded custom wordlists (v1 ships curated wordlists seeded into the database)
- Advanced visual monitoring dashboard
- System health-check / monitoring endpoint (disk / DB responsiveness / scanner availability)
- Session export/import and session merging

## Ethical & Safety Constraints (binding on all specs)

- Abyssum is for **authorized** testing only; docs and UI must reinforce scope discipline.
- Default request pacing must be conservative; the user-set delay is a hard floor.
- **Automated tests must never hit real third-party targets.** Scanner specs are verified
  against local mock HTTP servers / fixtures only.

## Resolved Decisions (formerly open questions)

These were decided deliberately; the specs reflect them.

1. **Auth depth** — local username/password only for v1 (no OAuth/SSO/teams). Argon2id hashing.
2. **Result visibility** — owner-only, with the `admin` role able to view all.
3. **Admin bootstrap** — the first registered user becomes admin.
4. **AI-assist surface** — analyze a single finding on demand (not whole-session auto-summary); outbound only; keyless endpoints supported (no `Authorization` header sent when no key is configured).
5. **Historical v1 data** — clean start. The old `data/abyssum.db` is **not** migrated; v2 begins with a fresh schema.
6. **Health checks** — out of scope for v1 (see Non-Goals).
