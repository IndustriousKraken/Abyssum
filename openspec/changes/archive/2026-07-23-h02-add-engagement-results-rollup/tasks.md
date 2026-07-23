# Tasks

- [x] On the engagement detail view, add a results rollup: a severity breakdown plus the findings
      aggregated across all sessions associated with the engagement.
- [x] Compute the severity breakdown via the existing subset-restricted Summary Counts, passing the
      engagement's associated sessions as the subset (no new persistence).
- [x] Scope the rollup to exactly the engagement's sessions; exclude other engagements' sessions
      and unassociated sessions.
- [x] Bound the rollup to sessions the operator may already see under per-user visibility
      (non-admin: their own; admin: all); never disclose via the rollup a session or finding the
      operator could not otherwise view.
- [x] Test: rollup counts and findings match the engagement's sessions and exclude others.
- [x] Test: a non-admin's rollup omits an engagement-associated session owned by another operator;
      an admin's rollup includes all of the engagement's sessions.
