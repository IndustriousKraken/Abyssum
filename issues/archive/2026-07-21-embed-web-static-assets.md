# abyssum-web ships no static assets — installed binary serves no CSS/JS

## Symptom

An installed release binary (`abyssum-web` from `install.sh`) serves the pages but
every `/static/*` request 404s, so there is **no styling and no HTMX/Alpine**: the
dashboard's lazily-loaded fragments (`stats`, `sessions`, `findings`) and live progress
never populate. Running from a source checkout happens to work for CSS only, which
masks the bug during development.

Reproduce: install `abyssum-web` on a host without the source tree, run it, then
`curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/static/app.css` → `404`.

## Root cause

Two compounding problems, plus a third latent one:

1. **The static dir is a compile-time path.** `abyssum-web/src/state.rs`
   `default_static_dir()` falls back to `PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("static")`.
   `env!("CARGO_MANIFEST_DIR")` is resolved **at build time**, so a CI-built release
   points at the build machine's checkout path (e.g. `/home/runner/work/Abyssum/...`),
   which does not exist on the target. `ServeDir::new(static_dir)`
   (`state.rs`, in `build_router`) then serves from a missing directory → 404s.

2. **The release ships only the binaries.** `install.sh` installs
   `("abyssum" "abyssum-web")` and nothing else; `.github/workflows/release.yml`
   copies only the binaries into `dist/`. The `static/` assets are never delivered to
   the target machine.

3. **htmx/alpine were never vendored.** `abyssum-web/src/view.rs` `page()` loads
   `/static/htmx.min.js` and `/static/alpine.min.js` (with a comment claiming
   install.sh vendors them "as a packaging step"), but `abyssum-web/static/` contains
   only `app.css` and `app.js`. So HTMX/Alpine are missing even from a source checkout;
   that "packaging step" does not exist.

## Recommended fix — make abyssum-web self-contained

Embed the static assets into the binary so it needs no companion files, matching the
project's "cross-compiled static binaries, no runtime deps" distribution posture.

- Vendor `htmx.min.js` and `alpine.min.js` into `abyssum-web/static/` (pinned
  versions, recorded so they're reproducible). This alone fixes source checkouts.
- Embed the `static/` directory into the binary (e.g. `rust-embed` / `include_dir`)
  and serve it through an embedded-asset handler (e.g. `axum-embed`, or a small custom
  handler that maps a path → embedded bytes + `Content-Type`) in place of the
  filesystem `ServeDir`.
- Keep `ABYSSUM_WEB_STATIC` as an **override**: when set, serve from that directory
  (useful for dev live-reload and custom themes); otherwise serve the embedded copy.
  Drop the `env!("CARGO_MANIFEST_DIR")` fallback entirely.
- Update the stale `view.rs` comment about install.sh vendoring the scripts.

An acceptable alternative, if embedding is rejected: package `static/` into the release
artifact, have `install.sh` install it to a known location, and make
`default_static_dir()` fall back to a runtime-resolvable path (e.g. beside
`std::env::current_exe()`, or a fixed share dir) rather than a build-time path. Embedding
is preferred — one file to ship, nothing to locate.

## How to verify

1. Build the binary, copy **only the binary** to a directory with no source tree, run it.
2. `curl -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/static/app.css` → `200`,
   and likewise for `app.js`, `htmx.min.js`, `alpine.min.js`.
3. Load the dashboard in a browser: it is styled, and the `stats`/`sessions`/`findings`
   fragments load (HTMX/Alpine present).
4. `ABYSSUM_WEB_STATIC=/some/dir abyssum-web` still overrides with that directory.

## Tasks

- [x] Vendor pinned `htmx.min.js` and `alpine.min.js` into `abyssum-web/static/`; record the versions.
- [x] Embed `abyssum-web/static/` into the binary and serve it via an embedded-asset handler, replacing the filesystem `ServeDir` for the default (no-override) case.
- [x] Keep `ABYSSUM_WEB_STATIC` as an override; remove the `env!("CARGO_MANIFEST_DIR")` fallback so no build-time path leaks into a shipped binary.
- [x] Update the `view.rs` comment that claims install.sh vendors htmx/alpine.
- [x] Add a test that the embedded assets are served (e.g. `GET /static/app.css` → 200 with a CSS content-type) so a future regression is caught.
- [x] Confirm the four referenced assets (`app.css`, `app.js`, `htmx.min.js`, `alpine.min.js`) all resolve in a binary run outside the source tree.
