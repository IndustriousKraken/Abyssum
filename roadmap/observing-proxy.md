---
title: Observing proxy (the differentiator)
status: deferred
added: 2026-07-16
---

A lightweight proxy that **observes and filters** API traffic — deliberately **not**
an intercepting proxy like Burp/ZAP. Non-blocking (traffic flows through
uninterrupted; capture is asynchronous), observable (every request/response indexed
and searchable), filterable (auto-surfaces auth tokens, IDOR/pagination candidates,
endpoints, error responses, with an interest score), and exportable (HAR, OpenAPI,
Postman, raw; plus an API for external tools/AI agents to consume and replay-with-
mutation).

Feeds Abyssum: observed traffic yields real targets and parameters to hand to the
scanner. A separable module with its own SQLite traffic store — connects to Abyssum
rather than living inside it (infrastructure-agnostic, loose coupling). This is the
defining differentiator from default tooling in the space.
