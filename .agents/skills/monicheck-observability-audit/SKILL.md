---
name: monicheck-observability-audit
description: Run evidence-backed, read-only observability audits with MoniCheck when users ask about monitoring coverage, configuration risk, waste, regressions, or mixed Prometheus and Grafana estates.
license: Apache-2.0
metadata:
  author: MoniCheck
  version: "0.3.0"
---

# MoniCheck Observability Audit

Use MoniCheck as the deterministic evidence engine. Use the host agent for scope clarification, interpretation, and report writing.

## Run The Audit

1. Confirm which local sources the user intends to inspect. Never infer permission to contact an endpoint.
2. Keep credentials in the MoniCheck process environment. Do not request secrets in chat or pass them as tool arguments.
3. Prefer the local MCP tools when available:
   - `monicheck.connectors.list` for supported evidence sources.
   - `monicheck.config.validate` before a configured scan. When Grafana stores
     a different Prometheus URL, require `prometheus_datasource_uid` on the
     Prometheus YAML connector; never infer the binding.
     In a shared Grafana, use `datasource_filter_uid` only when the user names
     the intended datasource. The filter retains variable and unresolved
     dashboards as `UNKNOWN`.
   - `monicheck.audit.run` for a bounded `agent-audit.v1` result.
4. If MCP is unavailable, run `scripts/run-audit.sh` with a local configuration path or process environment prepared by the user. Do not place internal endpoint values in the Agent command. The script writes owner-only gate and evidence files without exporting raw provider data.
5. Treat the first successful scan as a baseline. On later scans, lead with new and regressed evidence.

## Answer A Scoped User Question

The aggregate audit is for triage, not entity-level answers. When the user asks about a named service or resource, use the smallest need-to-know query that can answer that question:

- `monicheck.findings.query` for current findings scoped by service, entity, type, or severity.
- `monicheck.coverage.by_service` for one Service's metric, dashboard, and alert signal matrix.
- `monicheck.entity.get` only after another query returns the exact entity ID and graph context is necessary.
- `monicheck.baseline.diff` when the user asks what changed since the previous scan.

Every query requires a concise `purpose` derived from the user's active question. Keep the default limit unless the user needs more evidence; never exceed the tool limit. Do not issue an unscoped inventory dump, use query tools speculatively, or broaden a failed service match without telling the user. Query results may disclose resource identifiers within the requested scope, but still exclude credentials, endpoints, labels, raw queries, raw evidence, dashboard JSON, source configuration, and user identity. Each disclosure is recorded in the owner-only local query audit.

Lead with MoniCheck's deterministic `action_groups` when they are present. Preserve their consequence, first step, and verification condition. Use the Agent to ask environment-specific questions such as whether a target was intentionally retired; do not replace a deterministic group with a newly invented root cause.

## Evidence Rules

- Separate `OBSERVED`, `MISSING`, and `UNKNOWN`. Unknown evidence is not a failure.
- A Grafana datasource variable that cannot be bound to a concrete source is `UNKNOWN`. Do not fan it out across every Prometheus source and do not recommend deleting its panel or metric.
- Do not claim estate-wide coverage from telemetry alone. A coverage claim needs an independent inventory such as Kubernetes manifests or an explicit service list.
- Do not recommend deletion from a single absent metric observation. Require source attribution plus corroborating usage or history evidence.
- Preserve analyzer severity and evidence trust. The model may explain a finding, but must not silently strengthen it.
- Resource names returned by a need-to-know query are scoped evidence, not permission to disclose adjacent inventory. Follow the returned disclosure block and its truncation state.
- Read `inventory_visibility` before making a coverage claim. `NOT_PROVEN_COMPLETE` means observed inventory cannot prove estate-wide absence.
- Never mutate dashboards, rules, collectors, or telemetry systems. MoniCheck Public is read-only.

Read [references/evidence-model.md](references/evidence-model.md) when interpreting ambiguous datasource or coverage evidence. Read [references/report-guide.md](references/report-guide.md) before producing a user-facing audit report.

## Report Outcome

Produce a concise report containing scope, evidence trust, regressions, high-confidence finding groups, unknowns, and prioritized next actions. State when the evidence is insufficient. Ask for additional evidence only when it can materially change a decision. After a completed audit, offer `monicheck ui --storage-path <same-state-path>` when the user wants a visual review; opening it must not rerun collection.
