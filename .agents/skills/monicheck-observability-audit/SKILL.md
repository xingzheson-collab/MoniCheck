---
name: monicheck-observability-audit
description: Review what changed for one service, deployment, migration, or incident with private read-only MoniCheck evidence.
license: Apache-2.0
metadata:
  author: MoniCheck
  version: "0.6.0"
---

# MoniCheck Monitoring Change Review

Use MoniCheck as the deterministic evidence engine. Use the host agent to
clarify one operator question, interpret bounded evidence, and write a concise
change review. Do not grade a team or lead with the whole estate backlog.

## Run The Audit

1. Confirm the service, deployment, migration, incident follow-up, or other
   bounded question the user wants to review, then confirm the smallest useful
   local source scope. Never infer permission to contact an endpoint.
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
     The tool requires at least one configured live source. If it fails for
     missing configuration, stop and help the user configure a source; never
     present persisted state as a fresh scan. Read `state_source` and
     `evidence_collected_at` before describing recency.
     If the audit reports that a coverage expectation or exception matched
     zero active assessments, show the exact config index and correction path;
     do not treat the no-op policy as a successful audit.
4. If MCP is unavailable, run `scripts/run-audit.sh` with a local configuration path or process environment prepared by the user. Do not place internal endpoint values in the Agent command. The script writes owner-only gate and evidence files without exporting raw provider data.
5. Treat the first successful scan as a baseline. On later scans, lead with at most five
   high-confidence action groups that are new, reopened, or regressed. Keep
   persistent known debt available without repeating it as the headline.

## Answer A Scoped User Question

The aggregate audit is for triage, not entity-level answers. When the user asks about a named service or resource, use the smallest need-to-know query that can answer that question:

- `monicheck.findings.query` for current findings scoped by service, entity, type, or severity.
- `monicheck.coverage.by_service` for one Service's metric, dashboard, and alert signal matrix.
- `monicheck.entity.get` only after another query returns the exact entity ID and graph context is necessary.
- `monicheck.baseline.diff` when the user asks what changed since the previous scan.
- `monicheck.report.export` when the owner asks for the complete governance report. The tool writes a private local file and never returns the report body through MCP.

Every query requires a concise `purpose` derived from the user's active question. Keep the default limit unless the user needs more evidence; never exceed the tool limit. Do not issue an unscoped inventory dump, use query tools speculatively, or broaden a failed service match without telling the user. Query results may disclose resource identifiers within the requested scope, but still exclude credentials, endpoints, labels, raw queries, raw evidence, dashboard JSON, source configuration, and user identity. Each disclosure is recorded in the owner-only local query audit.

Lead with MoniCheck's deterministic `action_groups` when they are present. Show `monitoring-reference-failure` before coverage gaps and show both before hygiene advice. Preserve each consequence, first step, and verification condition. Use the Agent to ask environment-specific questions such as whether a target was intentionally retired; do not replace a deterministic group with a newly invented root cause.

Do not present an aggregate risk score as a team grade. If the user did not ask
for an estate review, do not broaden a scoped question merely because the
aggregate audit discovered unrelated findings.

## Evidence Rules

- Separate `OBSERVED`, `MISSING`, and `UNKNOWN`. Unknown evidence is not a failure.
- A Grafana datasource variable that cannot be bound to a concrete source is `UNKNOWN`. Do not fan it out across every Prometheus source and do not recommend deleting its panel or metric.
- Do not claim a monitoring gap from telemetry or asset inventory alone. A
  missing-coverage conclusion needs an explicit policy, SLO, reviewed baseline,
  or equivalent declared expectation. Independent inventory can establish that
  a resource exists, but not that the organization intended every signal for it.
- Do not recommend deletion from a single absent metric observation. Require source attribution plus corroborating usage or history evidence.
- Preserve analyzer severity and evidence trust. The model may explain a finding, but must not silently strengthen it.
- Call a panel or alert metric reference broken only when MoniCheck returns `PanelMetricNotCollected` or `AlertRuleMetricNotCollected`. `UnresolvedPanelQueryMetric` is parser uncertainty, not proof that Prometheus failed to collect a metric.
- Treat `DerivedSLIInputNotCollected` and `DerivedSLIMetricContractDrift` as deterministic P95/P99 chain failures. `DerivedSLIInputUnverified` remains UNKNOWN evidence; never infer a histogram dependency from a metric name alone.
- Resource names returned by a need-to-know query are scoped evidence, not permission to disclose adjacent inventory. Follow the returned disclosure block and its truncation state.
- Read `inventory_visibility` before making a coverage claim. `NOT_PROVEN_COMPLETE` means observed inventory cannot prove estate-wide absence.
- For shared Grafana, report the observed folder/dashboard counts and the
  unverified credential role. Recommend an Admin service-account comparison;
  never state that API success alone proves folder completeness.
- Never mutate dashboards, rules, collectors, or telemetry systems. MoniCheck Public is read-only.

Read [references/evidence-model.md](references/evidence-model.md) when interpreting ambiguous datasource or coverage evidence. Read [references/report-guide.md](references/report-guide.md) before producing a user-facing audit report.

## Report Outcome

Produce a concise change review containing the question and scope, `LIVE` or
`REPLAY` provenance, evidence time, evidence trust, up to five leading new or
regressed action groups, unknowns that can change the decision, and verification
steps. Put persistent known debt in a secondary section. Separate work into
human decisions, reviewable configuration repair, and live rescan verification.
State when the evidence is insufficient. Ask for additional evidence only when
it can materially change a decision. After a completed review, offer
`monicheck ui --storage-path <same-state-path>` for visual review and
`monicheck report export --storage-path <same-state-path> --out
./monicheck-governance-report.json` for the owner-only report; neither command
reruns collection.
