# RFC-0336: Monitoring Control Failures

- Status: Implemented for v0.7.4
- Scope: Public Local evidence, Agent action groups, Local UI

## Problem

Enterprises rarely lack monitoring assets. Their monitoring systems lose control:
dashboards outlive the metrics they query, alerts retain expressions that can no
longer evaluate, declared coverage outruns collected evidence, and large hygiene
backlogs hide failures that create false confidence during an incident.

## Decision

MoniCheck places exact broken monitoring references ahead of metadata hygiene.
`PanelMetricNotCollected`, `AlertRuleMetricNotCollected`, and
`RecordingRuleInputNotCollected` require an explicit Grafana-to-Prometheus
inventory binding and an absent metric relationship in that bound inventory.
They form the `monitoring-reference-failure` action group with a restore/correct
first step and same-datasource verification.

`UnresolvedPanelQueryMetric` remains parser uncertainty and is not evidence that
Prometheus failed to collect a metric. Datasource variables, mixed datasources,
partial inventory, and unverified ACL reach remain UNKNOWN or WARNING.
`BrokenDashboard` is WARNING because Grafana health/detail status alone does not
prove a metric reference is dead.

## Product boundary

The public engine and any paid workflow must share the same evidence result.
Paid workflow may add lifecycle, ownership, scheduling, tenant views, and ticket
integration, but cannot sell stronger evidence or hide accuracy behind a paywall.

## Deferred

High-impact guard correlation, golden-signal baselines, and derived SLI dependency
chains require separate real-environment validation and are not claimed here.
