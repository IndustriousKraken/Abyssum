# Design

**Separable module.** The proxy is its own surface over a shared core, consistent with
the roadmap's "connects to Abyssum rather than living inside it." It gets its own binary
(or subcommand) and its own SQLite traffic store, distinct from the scan result store, so
proxy traffic and scan findings stay cleanly separated.

**Observe, don't intercept.** "Not an intercepting proxy" means non-blocking and non-
modifying: traffic is never held on a breakpoint and never altered in flight. To *observe*
HTTPS content (the whole point — auth tokens, IDOR params live in the body), the proxy
still TLS-terminates using a locally-generated CA the operator trusts on their test client.
This is TLS termination for observation, not interception in the Burp sense. Plain
CONNECT/opaque tunnelling would only expose SNI + timing, losing the value.

**Non-blocking capture.** The response is written back to the client as it streams; the
captured copy is handed to an async writer (channel → background task) that persists to the
traffic store off the hot path. A slow or failing store must never stall the proxied
client — capture is best-effort and bounded (bodies truncated at a size limit).

**Traffic store.** A dedicated SQLite DB with an exchanges table indexed for query by
endpoint, param, header, status, and time. Reuses the existing sqlx/migration approach.

**Ethos.** The proxy is passive by default and adds no traffic of its own — it only
observes what the operator's client already sends.
