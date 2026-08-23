# RFC-0332: Actionable Local Audit

Status: Expanded for v0.7.3

## Problem

The v0.7.1 Agent contract contained useful `action_groups`, coverage
assessments, and `inventory_visibility`, but the Local UI exposed only aggregate
counts and a pointer to MCP. Users could prove that the engine was correct and
still fail to find a useful first action within ten minutes.

## Decision

The Local UI consumes a read-only `agent-audit.v1` projection rebuilt from
durable state. It renders consequence-based action groups, splits generic
configuration backlog by resource type under `hygiene-backlog/*`, and keeps
inventory completeness explicitly unproven.

Coverage is an action list rather than one score. Missing and unknown signals
are shown per service, UNKNOWN supplies an evidence-source command, MISSING can
copy a reviewed and time-bounded exception template, and Coverage links back to
the related Agent action family. The denominator states that UNKNOWN is
excluded and is never counted as healthy.

YAML governance policy supports expectations and exceptions with service,
namespace, or one-label scopes. Datasource-health findings remain collected but
are deprioritized behind other findings of the same severity in the Top-20.

## Boundaries

- Opening persisted state never contacts providers or runs analyzers.
- The UI does not turn approximate or unknown evidence into deletion advice.
- Copied exception YAML is a starter only; owner, reason, and expiry require
  explicit review before the next scan.
- A 15-minute activation target is retained. Release testing records scan time,
  but provider latency is not misrepresented as deterministic local CPU cost.

## Verification

Focused Go tests cover action grouping, read-only audit projection, strict YAML
policy, scope validation, coverage honesty copy, and CLI flag conflicts. Release
QA reopens a real persisted audit, checks desktop and mobile layouts, and builds
all four supported binaries from the reviewed Local-only export.

v0.7.3 adds a dedicated serve-only connector empty state, prevents CRITICAL
hygiene presentation, and validates that configured expectations and
exceptions affect the inventory collected by the same scan.
