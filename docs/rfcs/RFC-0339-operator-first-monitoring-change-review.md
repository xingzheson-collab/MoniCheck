# RFC-0339: Operator-First Monitoring Change Review

Status: Accepted
Date: 2026-09-01

## Decision

MoniCheck Public is a private, agent-native monitoring change reviewer for one
SRE question. It leads with new and regressed evidence for a service, change,
migration, or incident follow-up. It does not grade a team, dump the full
estate backlog as first value, or infer that every unmonitored resource is a
defect.

Coverage failure requires independent declared intent. Missing, Unknown,
Observed, and Exempt remain distinct. AI can request context and explain facts;
it cannot invent an SLA, owner, business impact, or expected monitoring policy.

## Priority

1. scoped review as the default entry;
2. new/regressed-first output bounded to five initial actions;
3. private local decisions: accepted, expected, false positive, fixed, or needs
   work, with reason and optional expiry;
4. decision-aware baseline comparison;
5. reviewable repair snippets or diffs plus verification commands;
6. external validation of repeat use and actionability before more product
   breadth or Managed infrastructure.

Analyzer count, Connector count, finding count, and global risk score are not
product success measures. The evidence engine remains deterministic and local;
provider mutation and automatic telemetry remain out of scope.
