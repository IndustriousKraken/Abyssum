# Tasks

- [ ] Define a per-scan options type in the core engine (open to extension by later features).
- [ ] Extend the session-creation path so a scan can be started with options; a scan started
      with none applies defaults and behaves as before.
- [ ] Record the options on the scan session.
- [ ] Expose the scan's options to scanners through the scan context (read-only), without
      adding any unpaced request path.
- [ ] Thread options from the surfaces: the web scan form and the CLI can supply them (the
      concrete options come from the feature changes that build on this).
- [ ] Test: a scan started with an option carries it to a scanner via the context; a scan
      started with none behaves identically to today; the context still exposes no unpaced
      request path.
