# Design

Builds on the `f01-add-observing-proxy-core` traffic store; read-and-emit plus a replay path.

**Export.** Pure functions over stored exchanges → bytes. HAR is a direct serialization of
exchanges. OpenAPI is *synthesized*: group by method+path template, infer parameters and
response shapes from observed examples — a best-effort description of what was seen, not a
guarantee of completeness (say so in the output). Raw is the verbatim request/response.
Postman collection export is a nice-to-have on the same read path.

**Programmatic access.** A read API over the store (query by the same dimensions the core
change indexes) so external tools/agents consume the capture. Read-only.

**Replay-with-mutation.** Take a stored exchange, apply operator-specified modifications
(method, URL, headers, body), and re-issue it. The replayed request goes through
`ScanContext::send` so it honors the pacing floor and User-Agent rotation — replay is
active traffic and must respect the same infrastructure-respect posture as a scan. The
replay's response is captured like any other exchange.
