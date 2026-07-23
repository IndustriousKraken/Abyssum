# Never probe a host outside the target's apex

## Why

Subdomain reconnaissance turns a candidate name into a request by interpolating it into a
URL string:

```rust
let url = Url::parse(&format!("{scheme}://{host}/"))
```

and the candidate set is normalized (trimmed, lowercased, deduped) but **never checked
against the target's apex**. A candidate containing a character that terminates the authority
therefore redirects the request to a different host entirely:

| wordlist entry | candidate built | host actually requested |
|---|---|---|
| `api` | `api.example.com` | `api.example.com` |
| `evil.com#` | `evil.com#.example.com` | **`evil.com`** |
| `evil.com/` | `evil.com/.example.com` | **`evil.com`** |

The scan then sends traffic to a third party the operator never authorized, while reporting
that it scanned their own domain. For a tool whose defining constraint is authorized testing
only, that is the most serious failure available to it.

Exposure today is narrow: the seeded wordlist is clean, so the only vector is the passive
source returning a crafted name. But user-supplied wordlists — where the intended workflow is
"copy a list from a repository and paste it in" — make this directly reachable, so the
invariant must exist before that feature does.

## What Changes

- Establish a scope invariant: reconnaissance SHALL only ever request hosts that are the
  target's apex or a subdomain of it. Any candidate from **any** source — passive discovery
  or wordlist brute-force — that falls outside the apex is discarded.
- Candidate names SHALL be constrained to valid DNS labels, so a name cannot carry characters
  that reinterpret a URL's authority.
- The request URL SHALL be built such that the candidate cannot alter the host component.
- Discarded out-of-scope candidates SHALL be counted and logged, not silently dropped.

## Out of scope

Wordlist import itself, and the per-scan brute-force toggle. This change is the safety
precondition both of those depend on.
