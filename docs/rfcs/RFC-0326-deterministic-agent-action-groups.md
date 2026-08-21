# RFC-0326: Deterministic Agent Action Groups

Status: Implemented MVP for v0.7.1

## Problem

A correct list of findings is not yet a work plan. v0.7.0 could reduce thousands of findings to aggregate counts, but still left the Agent to invent root-cause grouping, operational consequence, first action, and verification language. That moves deterministic work into a probabilistic layer and can produce different advice for the same evidence.

## Decision

MoniCheck now emits bounded `action_groups` in both `agent-audit.v1` and `agent-findings-query.v1`. The engine deterministically maps finding types into operational families, merges repeated findings, selects the highest severity, lists the contributing finding types, and attaches fixed consequence, first-step, and verification templates.

The first families cover target telemetry loss, Service coverage gaps, dashboard integrity, metric contract drift, alert delivery, telemetry cost, and a conservative configuration-risk fallback. Aggregate audit groups contain no resource identifiers. A scoped need-to-know query may include up to ten affected resource references because that disclosure already carries a user purpose, result bound, truncation state, and local audit receipt.

## Responsibility Split

The engine owns repeatable grouping, severity, consequence vocabulary, first-step template, and verification condition. The Agent may explain the group, ask whether a resource is intentionally retired, and draft a ticket, but it must not strengthen the evidence state or replace the deterministic template with an unsupported claim.

## Current Boundary

Service-scoped finding queries already use the resource graph to select resources related to the requested Service, so their action groups are bounded to that graph-derived scope. The aggregate action groups merge by operational family and do not yet claim estate-wide causal clustering across multiple Services, Jobs, Exporters, or namespaces. A later iteration may add deterministic graph-root incident clusters after real-estate validation; this MVP does not label broad family grouping as a proven root cause.

Group counts cover every matched Finding even when the item list is truncated.
Affected resource identifiers are drawn only from the already-disclosed item
window, so grouping cannot bypass the query's identifier limit.

## Acceptance

- Thirty repeated configuration findings produce one deterministic action group.
- A scoped Redis `BrokenTarget` query produces one `target-telemetry-loss` group with one affected resource.
- Every group contains a consequence, first step, and verification condition.
- Aggregate groups contain no resource names or IDs.
- Query groups inherit the need-to-know disclosure bound and local audit receipt.
- A one-item result window still reports every action family present in the
  complete matched set without disclosing identifiers outside that window.
