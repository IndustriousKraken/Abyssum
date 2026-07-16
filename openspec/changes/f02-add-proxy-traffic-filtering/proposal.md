# Add observing-proxy traffic filtering & interest scoring

## Why

A capture store fills up fast; most of it is noise. The proxy's value is surfacing the few
exchanges worth a human's attention — the auth token that just went by, the numeric id in
a URL that smells like an IDOR, the 500 that leaked a stack trace. This change scores
captured traffic by interest and auto-flags the security-relevant elements, turning the
raw stream into a triage view.

## What Changes

- Assign an interest score to captured exchanges and surface the higher-interest ones.
- Auto-flag security-relevant elements: authentication tokens and cookies, object-
  reference / pagination parameters (IDOR candidates), API endpoints, and error responses.

Filtering runs over the captured store, not inline in the relay path, so it never affects
the proxy's non-blocking behavior.
