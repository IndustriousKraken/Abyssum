# Add observing-proxy export & programmatic access

## Why

Captured traffic is most useful when it can leave the proxy — into Burp/Postman for manual
work, into an OpenAPI spec that documents what the API actually does, or into an external
tool or AI agent that consumes the stream and replays requests with tweaks. This change
adds the export and access seam that turns the traffic store into something other tools
(and Abyssum's own scanners, later) can build on.

## What Changes

- Export captured traffic in interchange formats: **HAR**, an **OpenAPI** description
  synthesized from observed endpoints, and **raw** request/response. (Postman collection
  export may be included as an additional format.)
- Expose captured traffic through an **API** so external tools/agents can query it.
- Support **replaying** a captured request with operator-specified modifications; the
  replayed request goes out through the paced request path and its result is captured.
