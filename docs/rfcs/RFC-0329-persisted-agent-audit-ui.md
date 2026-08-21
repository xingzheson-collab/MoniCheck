# RFC-0329: Persisted Agent Audit UI

Status: Implemented for v0.7.1

## Problem

The Agent path produced useful local evidence without a direct product entry
for reviewing the same persisted result.

## Decision

`monicheck ui --storage-path <path>` opens an existing completed Local state
without contacting providers or rerunning analyzers. The loopback UI adds an
`Agent audit` view and reports `PERSISTED_AGENT_AUDIT` as its state source.

## Boundaries

- Opening the UI is read-only with respect to providers.
- The view does not imply inventory completeness.
- Full owner evidence remains local.
- Missing or incomplete state fails closed.

## Verification

Runtime and Local UI contract tests prove persisted-state loading, the Agent
deep link, and the no-rerun explanation.
