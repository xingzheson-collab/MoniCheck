# RFC-0325: Need-To-Know Agent Query Surface

Status: Implemented for v0.7.1

## Problem

`agent-audit.v1` deliberately removed resource names and grouped findings for safe first-pass triage. In v0.7.0 that aggregate was also the deepest Agent-visible result. An Agent could say that eleven targets were broken, but could not answer a user's scoped question such as "Is Redis monitoring healthy?" This made the Agent path broader than the Local UI but materially shallower.

Privacy must prevent unintended disclosure, not prevent an owner from investigating their own environment. An unrestricted inventory dump is still unacceptable, so entity disclosure needs scope, bounds, purpose, and an audit record.

## Decision

Keep `agent-audit.v1` aggregate and privacy-safe. Add four local stdio MCP tools for user-initiated drill-down:

1. `monicheck.findings.query` filters current active findings by Service, entity, finding type, or severity.
2. `monicheck.coverage.by_service` returns one Service's deterministic signal matrix.
3. `monicheck.entity.get` returns one exact entity, bounded graph relationships, and current findings.
4. `monicheck.baseline.diff` returns bounded changes between the latest two Local snapshots.

Every call requires a concise `purpose` derived from the user's active question. Result limits default to 20 and cannot exceed 50. A findings query requires at least one scope filter; entity lookup requires an exact ID returned by MoniCheck. Ambiguous selectors fail visibly and require an exact MoniCheck entity ID instead of silently broadening scope.

Service scope follows recursive `BELONGS_TO` ownership and directed
`PRODUCES` edges. A dashboard, panel, or alert that consumes scoped evidence
is included as a one-hop terminal consumer; its other metric edges are never
traversed. This prevents a shared dashboard from turning one Service query into
an estate-wide result.

## Disclosure Contract

Query results include `disclosure.mode=NEED_TO_KNOW`, the purpose, effective scope, limit, result count, truncation state, disclosed identifier fields, excluded fields, and an audit event reference.

Entity IDs and names may be returned within the requested scope. Credentials, endpoint URLs, labels, raw queries, raw evidence, dashboard JSON, source configuration, and user identity remain excluded. Recommendations are deterministic Analyzer text and are bounded; raw evidence is represented only by a count.

Each successful disclosure appends an `agent-query-audit.v1` JSONL event beside the Local state file. The file is owner-only mode `0600`; it records the tool, purpose, scope, bound, result count, truncation, and identifier field classes, not the returned evidence body.

## Safety

- All four tools are provider-read-only and never contact an observability source.
- Query tools read an existing regular Local state file and fail if no audit state exists.
- The audit path rejects symlinks and non-regular files.
- `UNKNOWN` remains distinct from `MISSING` in service coverage.
- A user-scoped name is not permission to disclose adjacent inventory.
- The Skill must not call query tools speculatively or perform an unscoped inventory dump.

## Acceptance

- A seeded Redis Service with one broken related target returns that target and no unrelated finding.
- A shared dashboard may be related to two Services, but querying either
  Service cannot pull the other Service's metrics through that dashboard.
- Service coverage reports metrics as observed and unavailable signal inventories as unknown.
- Entity lookup returns bounded direct graph relationships and current findings.
- Missing purpose, missing scope, a limit above 50, an ambiguous selector, or a linked state/audit file fails closed.
- The disclosure audit is mode `0600` and contains no endpoint or raw evidence.
- Public export, MCP contract tests, Skill contract tests, and full Go tests pass.

## Follow-Up

P19 deterministic incident grouping, consequence statements, and action templates consume this query surface next. P15 datasource binding, P16 inventory visibility, P18 Agent-result UI entry, and datasource filtering remain separate evidence-quality work; this RFC does not claim they are solved.
