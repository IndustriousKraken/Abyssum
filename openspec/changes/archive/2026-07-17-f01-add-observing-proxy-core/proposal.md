# Add the observing proxy — core (pass-through + capture)

## Why

The observing proxy is Abyssum's flagship differentiator (`roadmap/observing-proxy.md`):
a lightweight proxy that **observes and filters** API traffic — deliberately *not* an
intercepting proxy like Burp/ZAP. It never pauses the operator on a breakpoint; it watches
quietly and records. The recorded traffic is a stream of real endpoints, parameters, and
tokens that later feeds the scanner.

This change is the foundation: relay traffic without blocking, and capture every exchange
into a dedicated, queryable traffic store. Filtering/scoring and export build on it in
follow-on changes.

## What Changes

- Add a proxy that relays HTTP/HTTPS traffic between a client and its destination
  **non-blockingly**: the destination's response is returned to the client without waiting
  on capture or analysis, and the proxy never holds traffic for operator action.
- Capture each relayed request and response asynchronously into a dedicated persistent
  **traffic store** (method, URL/endpoint, headers, status, timing, body within size
  limits), surviving process restart and queryable by endpoint, parameter, header, status,
  and time.

## Out of scope (follow-on changes)

- Interest scoring / auto-flagging of security-relevant traffic (`f02-add-proxy-traffic-filtering`).
- Export and programmatic access / replay (`f03-add-proxy-traffic-export`).
- Handing observed targets/parameters directly to a scan (target chaining).
