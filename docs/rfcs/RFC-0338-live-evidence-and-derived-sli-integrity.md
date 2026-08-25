# RFC-0338: Live Evidence And Derived SLI Integrity

- Status: Implemented in Public v0.7.6
- Scope: Public Local runtime, Agent contract, derived SLI analysis, Local UI

## Problem

A zero-source `monicheck.audit.run` could open durable state, run analyzers
against old resources, and present the result as a successful current audit.
Time-sensitive checks such as `StaleTargetScrape` then created false
regressions from evidence that had not been recollected.

MoniCheck also modeled metric references generically. It could not explain
whether a P95/P99 `histogram_quantile()` expression had a proven path through
its metric or recording-rule input to current collection, or whether a
histogram/summary TYPE conflict invalidated that percentile assumption.

## Decision

### Live evidence boundary

`audit.run` requires at least one configured live source and fails before
opening or mutating durable state when none exists. A YAML file that produces
zero connectors also fails closed.

`agent-audit.v1` exposes `state_source` as `LIVE` or `REPLAY` and includes
`evidence_collected_at`. Persisted UI and query paths never contact providers,
rerun analyzers, or create a new baseline. They cannot turn old timestamps into
new regression evidence.

### Derived SLI integrity

MoniCheck uses the official PromQL parser to recognize
`histogram_quantile()`. It does not infer percentile intent from metric or
recording-rule names.

For each proven expression, the analyzer traces explicit `USES` and
`PRODUCES` relationships through Metric, RecordingRule, and Target resources:

- an input absent from an exactly bound Prometheus inventory is
  `DerivedSLIInputNotCollected` (CRITICAL);
- conflicting or incompatible histogram TYPE evidence is
  `DerivedSLIMetricContractDrift` (CRITICAL);
- a placeholder or incomplete chain is `DerivedSLIInputUnverified` (WARNING);
- no statically resolvable metric input remains a bounded structural warning.

An UNKNOWN chain is not promoted to missing. Native histograms and recording
rules with nonstandard names are not rejected from suffix matching alone.

## Operator delivery

The Agent summary includes a UI command template, an owner-only report export
command, five scoped question examples, and separate human-decision,
configuration-repair, and live-rescan responsibilities.

`monicheck report export` and `monicheck.report.export` write the latest full
report to a user-selected `0600` local file. MCP returns only the write receipt,
not the report body.

## Non-goals

- anomaly detection or failure prediction;
- querying time-series values to decide whether a percentile is anomalous;
- inferring golden-signal policy from names;
- turning UNKNOWN inventory into a missing claim;
- modifying dashboards, rules, or telemetry configuration.

## Acceptance

- zero-source Agent audit fails without mutating or replaying state;
- LIVE and REPLAY provenance plus evidence time are explicit;
- replay never reruns time-sensitive analyzers or changes the baseline;
- official AST tests cover literal and dynamic histogram quantiles;
- observed target and recording-rule chains pass;
- exact missing, TYPE drift, and unverified inputs remain distinct;
- report export writes `0600` and does not return full content through MCP;
- Local UI shows provenance, evidence time, action groups, and operator handoff.
