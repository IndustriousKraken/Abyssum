# Vendored front-end libraries

These minified copies are checked in and **embedded into the `abyssum-web`
binary** at build time (see `src/assets.rs`), so a shipped binary needs no
companion files. Pinned versions, kept reproducible:

| File            | Library   | Version | Source                                                        |
| --------------- | --------- | ------- | ------------------------------------------------------------- |
| `htmx.min.js`   | htmx      | 2.0.4   | https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js             |
| `alpine.min.js` | Alpine.js | 3.14.8  | https://cdn.jsdelivr.net/npm/alpinejs@3.14.8/dist/cdn.min.js  |

`app.css` and `app.js` are first-party and live here too; all four are the
`/static/*` assets `view.rs` references.

To refresh, re-download the pinned version (or bump the version here and in this
table) into this directory. The standard (non-CSP) Alpine build is used
deliberately — it relies on `Function()`, which the `script-src 'unsafe-eval'`
CSP in `state.rs` already allows.
