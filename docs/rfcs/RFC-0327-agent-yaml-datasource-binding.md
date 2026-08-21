# RFC-0327: Agent YAML Datasource Binding

Status: Implemented for v0.7.1 Candidate

## Problem

The Local shortcut could bind a reachable Prometheus endpoint to a Grafana
datasource UID, but `monicheck.audit.run` uses YAML and could not express that
identity. Shared Grafana audits therefore regressed to URL matching in the
Agent path.

## Decision

A Prometheus connector may declare `prometheus_datasource_uid`. During config
construction MoniCheck binds that UID to the connector's canonical Prometheus
URL before connector namespacing. The field is valid only on Prometheus.

The first contract intentionally supports one explicit binding with exactly one
Grafana connector. Missing Grafana, multiple Grafana connectors, multiple
bindings, or use on another connector type fails validation. This keeps the
common configuration small and prevents a guessed cross-stack identity.

No endpoint or UID is returned in `agent-audit.v1`; configuration remains
owner-local. Multi-Grafana and multiple-Prometheus binding requires a later
versioned mapping contract rather than overloaded inference.

## Acceptance

- A Prometheus plus Grafana YAML config with one UID validates.
- A binding with multiple Grafana connectors fails closed.
- Unknown YAML fields and literal secrets remain rejected.
- Public docs and the example configuration describe the optional binding.
