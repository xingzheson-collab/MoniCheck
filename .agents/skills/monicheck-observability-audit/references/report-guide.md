# Report Guide

Write for an SRE who needs to decide what to inspect next, not for an analyzer author.

## Recommended Structure

1. **Scope**: sources contacted, scan boundary, and baseline state.
2. **Evidence trust**: healthy connectors, incomplete sources, and attribution unknowns.
3. **What changed**: regressions and improvements since the previous local snapshot.
4. **High-confidence findings**: grouped by operational decision, with counts and severity.
5. **Coverage gaps**: only gaps with an independent expected inventory; list other cases as unknown.
6. **Cost opportunities**: estimates with assumptions and confidence, never guaranteed savings.
7. **Next actions**: at most five ordered actions, each tied to evidence.

## Writing Rules

- Prefer grouped findings over listing hundreds of repeated instances.
- Distinguish an analyzer result from the agent's interpretation.
- Explain why an action is safe enough to consider.
- State the missing evidence that prevents a stronger conclusion.
- Never reproduce credentials, endpoint URLs, resource names, labels, raw queries, or dashboard JSON from private artifacts unless the user explicitly asks to inspect a local owner-only report.
