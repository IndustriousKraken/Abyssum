# Tasks

- [x] Add a proxy surface (binary or subcommand) that relays HTTP/HTTPS between a client
      and its destination, TLS-terminating with a locally-generated CA so request/response
      content is observable.
- [x] Return the destination's response to the client without waiting on capture or
      analysis; never hold traffic on a breakpoint or modify it in flight.
- [x] Hand each exchange to an async writer (channel → background task) that persists it to
      a dedicated SQLite traffic store off the hot path; a slow/failing store must not stall
      the client.
- [x] Capture method, URL/endpoint, headers, status, timing, and body (truncated to a size
      limit) for each exchange; ensure captures survive process restart.
- [x] Index the store so exchanges are queryable by endpoint, parameter, header, status,
      and time; expose a basic query path.
- [x] Test: a relayed exchange is returned to the client unmodified and, asynchronously,
      appears in the traffic store and is retrievable by endpoint/status/time.
