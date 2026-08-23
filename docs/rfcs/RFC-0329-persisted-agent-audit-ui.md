# RFC-0329: Persisted Agent Audit UI

Status: Expanded for v0.7.2

## Problem

The Agent path produced useful local evidence without a direct product entry
for reviewing the same persisted result.

## Decision

`monicheck ui --storage-path <path>` and the discoverable alias
`monicheck local --serve-only --storage-path <path>` open completed Local state
without contacting providers or rerunning analyzers. The loopback UI adds an
`Agent audit` view, reports `PERSISTED_AGENT_AUDIT` as its state source, and
renders deterministic action groups plus inventory visibility from durable
state.

The Coverage view renders top missing and unknown service-signal rows, names
the denominator, provides evidence-source commands for UNKNOWN, links to Agent
actions, and can copy a time-bounded YAML exception template for MISSING.

## Boundaries

- Opening the UI is read-only with respect to providers.
- The view does not imply inventory completeness.
- Full owner evidence remains local.
- Missing or incomplete state fails closed.

## Verification

Runtime and Local UI contract tests prove persisted-state loading, the Agent
deep link, the read-only audit endpoint, action/visibility rendering, coverage
honesty copy, and the no-rerun explanation.
