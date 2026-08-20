# RFC-0324: Agent-Native Public Toolkit

Status: Implemented MVP

## Summary

MoniCheck Public becomes a local evidence toolkit for existing AI agents. The deterministic Go Connector, graph, Analyzer, Coverage, Risk, Cost, report, and snapshot work remains the product core. A portable Agent Skill supplies domain decisions and report workflow; a local stdio MCP server supplies structured tool invocation.

This changes the first user experience, not the evidence engine. MoniCheck does not build a second general-purpose chat product and does not require a hosted language model.

## Product Boundary

Public includes the Local CLI and UI, existing deterministic engine, one portable `monicheck-observability-audit` Agent Skill, a local stdio MCP server, local baselines, and privacy-safe outputs. Hosted scheduling, organization history, shared workflow, access control, and managed delivery remain outside the public repository.

## Architecture

1. The CLI collects evidence, runs analyzers, persists snapshots, and calculates regression.
2. MCP exposes stable structured tools without accepting credentials as arguments.
3. The Agent Skill defines scope, evidence semantics, interpretation constraints, and report shape.
4. The user's agent turns bounded evidence into a readable decision report.

The model is not authoritative for source facts. An Analyzer result may be explained or grouped, but its evidence state and severity cannot be silently strengthened.

## MCP Contract

`monicheck mcp --transport stdio` exposes:

- `monicheck.connectors.list`;
- `monicheck.config.validate`;
- `monicheck.audit.run`.

All tools are non-destructive. Audit arguments contain only local configuration and state paths; endpoints and credentials are inherited by the MoniCheck process. Execution contacts only user-selected systems, updates local snapshot history, and returns bounded `agent-audit.v1` evidence.

## Evidence Safety

1. `UNKNOWN` is not `MISSING`.
2. An unresolved Grafana datasource variable is not evaluated against every Prometheus source.
3. Telemetry alone cannot prove estate-wide coverage without an independent expected inventory.
4. A deletion recommendation requires unambiguous source attribution plus corroborating history or usage evidence.

Agent output excludes credentials, endpoint URLs, resource names, labels, raw queries, raw evidence, dashboard JSON, source configuration, and user identity. Full owner-only reports remain local.

## Non-goals

- a MoniCheck-specific model or chat UI;
- automatic remediation or provider mutation;
- automatic report upload;
- one skill per analyzer;
- model-based replacement of deterministic analyzers.
