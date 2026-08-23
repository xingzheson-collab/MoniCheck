# RFC-0333: Fail-Visible Governance Intent

Status: Implemented for v0.7.3

## Problem

A syntactically valid coverage expectation or exception could affect zero
Services and still let the audit succeed. A misspelled label key therefore
looked identical to a valid policy with no gaps. At the same time,
`JobWithoutHealthyTarget` and `BrokenTarget` findings from one target outage
were split into incident and hygiene families, and a generic hygiene group
could carry CRITICAL severity.

Grafana inventory had a related honesty gap: a successful search response did
not prove that the credential could read every ACL-protected folder.

## Decision

Local configuration is reconciled against the inventory collected by the same
scan before analyzers run:

- every enabled custom expectation must match at least one active Service;
- every configured exception must match an active Service, an applicable
  expectation, and one required signal;
- zero-effect intent fails the audit with the exact configuration index and a
  correction path;
- validated intent is persisted before analyzers execute, so the current
  report and findings use the current YAML rather than the previous scan's
  state.

Agent action grouping places `BrokenTarget` and
`JobWithoutHealthyTarget` in `target-telemetry-loss`. Unclassified CRITICAL
findings are promoted to `configuration-risk`; `hygiene-backlog/*` is reserved
for reviewable backlog and never carries CRITICAL severity.

`coverage.by_service` returns every matching built-in and custom assessment.
It is not truncated by the generic finding-query limit.

Grafana emits a provider diagnostic with observed folder/dashboard counts,
`credential_role=UNVERIFIED`, and
`folder_reachability=NOT_PROVEN_COMPLETE`. The Agent and Local UI recommend an
Admin service-account comparison without claiming that an Admin-key retest has
already happened.

## Operator Flow

1. Run an audit and obtain exact Service IDs.
2. Add expectations. A selector matching zero Services fails visibly.
3. Copy an exception starter from Coverage, review owner/reason/expiry, and
   scan again. An unknown Service ID fails visibly.
4. For shared Grafana, repeat with an Admin-scoped credential and compare
   observed folder/dashboard counts before treating inventory as complete.

## Boundaries

- Configuration validation does not infer labels, aliases, or intended scope.
- An Admin credential improves reachability but does not by itself prove
  pagination, tenant, or organization completeness.
- Existing persisted intent is not silently deleted when a new config fails.
- Identity aliases and durable intent history are separate design work.

## Verification

Regression tests cover zero-match expectations, ineffective exceptions,
same-scan analyzer ordering, all-assessment service queries, target outage
grouping, CRITICAL hygiene promotion, Grafana ACL diagnostics, and the
serve-only connector empty state.
