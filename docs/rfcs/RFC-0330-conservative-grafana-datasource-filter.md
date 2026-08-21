# RFC-0330: Conservative Grafana Datasource Filter

Status: Implemented for v0.7.1

## Problem

A shared Grafana can contain dashboards for many projects. Ingesting every
dashboard can crowd the report with known foreign evidence, while expanding a
datasource variable across every Prometheus source creates false conclusions.

## Decision

A Grafana YAML connector may set `datasource_filter_uid`. The filter excludes
only dashboards whose effective datasource references are all concrete and
belong to another datasource. A matching concrete reference includes the
dashboard. Dynamic, mixed, default, absent, builtin, or unresolved attribution
is retained as `UNKNOWN`.

The connector emits included, excluded, and unknown counts plus
`unknown_policy=retain`.

## Boundaries

- The option is disabled by default.
- It filters dashboard ingestion, not Grafana alert-rule discovery.
- Retained unknown dashboards cannot justify deletion.

## Verification

Tests cover selected, foreign, dynamic, and mixed unresolved dashboards, and
validate the diagnostic contract.
