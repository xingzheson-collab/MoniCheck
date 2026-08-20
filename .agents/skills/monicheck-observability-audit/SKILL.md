---
name: monicheck-observability-audit
description: Run evidence-backed, read-only observability audits with MoniCheck when users ask about monitoring coverage, configuration risk, waste, regressions, or mixed Prometheus and Grafana estates.
license: Apache-2.0
metadata:
  author: MoniCheck
  version: "0.1.0"
---

# MoniCheck Observability Audit

Use MoniCheck as the deterministic evidence engine. Use the host agent for scope clarification, interpretation, and report writing.

## Run The Audit

1. Confirm which local sources the user intends to inspect. Never infer permission to contact an endpoint.
2. Keep credentials in the MoniCheck process environment. Do not request secrets in chat or pass them as tool arguments.
3. Prefer the local MCP tools when available:
   - `monicheck.connectors.list` for supported evidence sources.
   - `monicheck.config.validate` before a configured scan.
   - `monicheck.audit.run` for a bounded `agent-audit.v1` result.
4. If MCP is unavailable, run `scripts/run-audit.sh` with a local configuration path or process environment prepared by the user. Do not place internal endpoint values in the Agent command. The script writes owner-only gate and evidence files without exporting raw provider data.
5. Treat the first successful scan as a baseline. On later scans, lead with new and regressed evidence.

## Evidence Rules

- Separate `OBSERVED`, `MISSING`, and `UNKNOWN`. Unknown evidence is not a failure.
- A Grafana datasource variable that cannot be bound to a concrete source is `UNKNOWN`. Do not fan it out across every Prometheus source and do not recommend deleting its panel or metric.
- Do not claim estate-wide coverage from telemetry alone. A coverage claim needs an independent inventory such as Kubernetes manifests or an explicit service list.
- Do not recommend deletion from a single absent metric observation. Require source attribution plus corroborating usage or history evidence.
- Preserve analyzer severity and evidence trust. The model may explain a finding, but must not silently strengthen it.
- Never mutate dashboards, rules, collectors, or telemetry systems. MoniCheck Public is read-only.

Read [references/evidence-model.md](references/evidence-model.md) when interpreting ambiguous datasource or coverage evidence. Read [references/report-guide.md](references/report-guide.md) before producing a user-facing audit report.

## Report Outcome

Produce a concise report containing scope, evidence trust, regressions, high-confidence finding groups, unknowns, and prioritized next actions. State when the evidence is insufficient. Ask for additional evidence only when it can materially change a decision.
