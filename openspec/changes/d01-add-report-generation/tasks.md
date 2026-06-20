# Tasks

## 1. Generator skeleton
- [ ] 1.1 Add a `ReportGenerator` in `abyssum-core` that loads a session and its findings via the persistence layer
- [ ] 1.2 Define a report format selector (markdown / json / csv / hackerone) and an options struct (include-evidence flag)
- [ ] 1.3 Filter loaded findings to the reportable set (vulnerability/exposure status), excluding benign/absent results
- [ ] 1.4 Return a not-found error when no session has the requested identifier

## 2. Built-in content tables
- [ ] 2.1 Add a per-finding-type remediation recommendation table with a generic fallback
- [ ] 2.2 Add a per-finding-type impact statement table with a generic fallback
- [ ] 2.3 Add a severity ranking helper (critical > high > medium > low > info) used for ordering

## 3. Markdown report
- [ ] 3.1 Render header metadata: target, scan date, scanner ids, session identifier
- [ ] 3.2 Render an executive summary with total findings and a per-severity count breakdown
- [ ] 3.3 Render findings grouped most-severe-first, each with type, severity, endpoint, description, and remediation
- [ ] 3.4 Include each finding's evidence when the include-evidence option is set; omit evidence blocks when it is not

## 4. JSON export
- [ ] 4.1 Render an export object with an export timestamp, session count, and a list of sessions
- [ ] 4.2 For each session include its metadata and its findings (type, severity, target, status, evidence)
- [ ] 4.3 Support exporting more than one session in a single export

## 5. CSV summary
- [ ] 5.1 Write a header row, then one row per reportable finding across the selected sessions
- [ ] 5.2 Include columns: session, target, scanner id, finding type, severity, endpoint, description
- [ ] 5.3 Ensure descriptions/evidence are correctly quoted/escaped

## 6. HackerOne export
- [ ] 6.1 Select the most-severe finding as the lead; break ties deterministically
- [ ] 6.2 Render Summary, Steps To Reproduce, Impact, and Supporting Material sections for the lead finding
- [ ] 6.3 Append remaining findings as a list of additional findings when more than one exists
- [ ] 6.4 Return an error when the session has no reportable findings

## 7. Report command surface
- [ ] 7.1 Add a `report` CLI subcommand taking a session id, a `--format markdown|json|csv|hackerone`, an output destination (stdout or `--output <file>`), and an evidence-omission flag
- [ ] 7.2 Wire the subcommand to the `ReportGenerator`; exit non-zero with a clear error for an unknown session id

## 8. Tests (local only — no network)
- [ ] 8.1 Build an in-memory fixture session with findings spanning several severities
- [ ] 8.2 Assert the Markdown report contains target, severity breakdown counts, and each finding's type/severity/endpoint/remediation
- [ ] 8.3 Assert evidence appears with include-evidence on and is absent with it off
- [ ] 8.4 Assert the CSV has a header plus exactly one row per reportable finding, correctly escaped
- [ ] 8.5 Parse the JSON export and assert session count, per-session metadata, and finding fields
- [ ] 8.6 Assert the HackerOne export leads with the most-severe finding and errors on a session with no reportable findings
- [ ] 8.7 Assert benign/non-finding results are excluded from every format
