# Tasks

## Storage & domain (engagements)

- [ ] Add durable storage for engagements (id, name, owner/creator, created-at) and for their
      documents (engagement id, kind: text | url | file, payload/blob + content type + filename,
      added-by operator, added-at), via a forward migration.
- [ ] Record the authorized-operator set per engagement; initialize it to exactly the creator.
- [ ] Add a nullable engagement association to scan sessions, recording which operator made it;
      a session with no engagement is valid and behaves as today.
- [ ] Enforce "at most one engagement per scan" (reassignment replaces, not accumulates).
- [ ] Enforce upload bounds: allowed document types and a maximum size; reject over-limit with a
      clear error rather than storing or truncating.

## Web surface (web-ui)

- [ ] Engagements pages: create, list (scoped to the operator's authorized set, admin sees all),
      and open one showing its associated scans and attached documents.
- [ ] Assign a scan to an engagement — both an optional selector on the start-scan form and an
      assign action on an existing session.
- [ ] Attach documents: paste text, supply a URL, or upload a file.
- [ ] Serve uploaded documents safely: fixed document content type, `X-Content-Type-Options:
      nosniff`, `Content-Disposition`, and a sandbox that prevents execution in the app's origin;
      never serve an upload as `text/html`.
- [ ] Render for reference: pasted text inline, URL as a link, PDF inline via the browser's native
      viewer (no client PDF library, no external code).
- [ ] Apply per-user visibility to engagements and their documents, mirroring session visibility,
      with admin override.

## Verification

- [ ] Test: an engagement is created, persisted, and reloads after restart with its owner and
      documents intact.
- [ ] Test: a scan associated with an engagement runs with unchanged targets, scanners, and pacing;
      an unassociated scan behaves identically to today.
- [ ] Test: an oversized or disallowed upload is rejected and not stored.
- [ ] Test: an uploaded document is served with a fixed content type and `nosniff` and cannot
      execute in the app's origin; a PDF renders inline without loading external code.
- [ ] Test: a non-admin cannot list, open, or fetch documents of an engagement they are not
      authorized for; an admin can.
