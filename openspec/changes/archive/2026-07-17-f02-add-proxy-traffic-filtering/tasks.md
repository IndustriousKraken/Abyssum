# Tasks

- [x] Analyze captured exchanges over the traffic store (on write or on query), never
      inline in the relay path.
- [x] Auto-flag security-relevant elements: auth tokens/cookies, object-reference /
      pagination parameters (IDOR candidates), API endpoints, and error responses.
- [x] Assign an additive interest score from the categories present and expose a view that
      surfaces higher-interest exchanges first.
- [x] Persist flags/score with the exchange so the triage view is queryable and stable
      across restarts.
- [x] Test: an exchange carrying an auth token and a numeric id is flagged in both
      categories and scores above a plain static-asset exchange; an error response is
      flagged as such.
