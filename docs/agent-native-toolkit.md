# Agent-Native Public Toolkit

MoniCheck Public is a local evidence toolkit for the AI agent the user already operates. It does not ship another chat UI or require a hosted model.

## Components

- **Agent Skill**: teaches the agent how to scope an audit, preserve evidence uncertainty, and write a useful report.
- **Local MCP server**: exposes versioned, read-only tools over stdio.
- **Go CLI and analyzers**: collect evidence and produce deterministic findings.
- **Local state**: stores snapshots and regression history on the user's machine.

The agent is an interpretation layer. It does not replace analyzer results, invent missing topology, or receive provider credentials.

## Install

Build MoniCheck, then install the skill for a compatible agent:

```bash
go build -o bin/monicheck ./cmd/monicheck
./scripts/install-agent-skill.sh --codex
```

The skill is also stored in `.agents/skills/monicheck-observability-audit` for clients that discover project or user-level Agent Skills.

Configure a local MCP client to launch the absolute binary path:

```json
{
  "mcpServers": {
    "monicheck": {
      "command": "/absolute/path/to/monicheck",
      "args": ["mcp"]
    }
  }
}
```

Endpoints and credentials remain in process environment variables or the local YAML configuration. MCP arguments accept only local configuration and state paths, so an agent does not need to receive an internal endpoint or secret value.

For Grafana, use a service-account token with read access to the folders,
dashboards, datasources, alert rules, and provisioning resources you intend to
audit. A token scoped to one organization or folder cannot prove estate-wide
visibility; the audit will keep inventory at `NOT_PROVEN_COMPLETE`. An Admin
role can improve API reach but does not bypass folder permissions, datasource
proxy restrictions, Enterprise access-control rules, or a reverse proxy that
blocks provisioning endpoints. Start with least privilege, inspect connector
diagnostics, and widen only the specific read permission that remains UNKNOWN.

When a shared Grafana stores a Prometheus datasource URL that differs from the
endpoint MoniCheck can reach, set `prometheus_datasource_uid` on the
Prometheus YAML connector. The initial YAML contract requires exactly one
Grafana connector and one explicit binding; ambiguous multi-Grafana
configurations fail closed instead of guessing.

For a shared Grafana that contains dashboards for unrelated projects, the
Grafana YAML connector may set `datasource_filter_uid`. MoniCheck excludes
only dashboards explicitly attributable to another datasource. Variable,
mixed, default, absent, and unresolved datasource references remain in scope as
`UNKNOWN`; the filter never treats uncertainty as proof that a dashboard is
irrelevant.

## MCP Tools

- `monicheck.connectors.list`: local connector catalog.
- `monicheck.config.validate`: validates a versioned YAML configuration without exposing secret values.
- `monicheck.audit.run`: contacts only user-selected sources, persists a local baseline, and returns bounded `agent-audit.v1` aggregate evidence.
- `monicheck.findings.query`: returns bounded current findings for a user-requested service, entity, type, or severity.
- `monicheck.coverage.by_service`: returns one Service's deterministic signal matrix without collapsing `UNKNOWN` into `MISSING`.
- `monicheck.entity.get`: returns one exact entity with bounded graph relationships and current findings.
- `monicheck.baseline.diff`: returns bounded item-level change evidence for the latest two Local snapshots.

The audit result excludes credentials, endpoint URLs, resource names, labels, queries, raw evidence, dashboard JSON, source configuration, and user identity. Entity identifiers are disclosed only when the user asks a scoped question and the agent calls one of the four query tools with a concise `purpose`. Each result is limited to at most 50 records, states whether it was truncated, lists the identifier fields disclosed, and appends an owner-only `agent-query-audit.v1` record beside the Local state file. Full owner-only reports remain local.

Both aggregate audits and scoped finding queries also include deterministic `action_groups`. MoniCheck merges repeated findings into operational families and supplies fixed consequence, first-step, and verification templates before the Agent explains them. Aggregate groups remain anonymous; scoped groups may name only the resources covered by the need-to-know disclosure.

Every aggregate audit and Service coverage query includes
`inventory_visibility`. Observed resources do not prove complete provider,
folder, pagination, tenant, or organization visibility, so MoniCheck reports
`NOT_PROVEN_COMPLETE` rather than making an estate-wide claim.

To review an existing Agent audit in the Local UI without contacting providers
or rerunning analyzers:

```bash
monicheck ui --storage-path /path/to/local-state.json
# Equivalent, more discoverable Local workflow:
monicheck local --serve-only --storage-path /path/to/local-state.json
```

Open the printed `?view=agent` loopback URL. The view reads the same durable
owner-only state used by MCP queries.

The Agent view renders deterministic action groups and an explicit inventory
visibility boundary. Coverage renders missing and unknown rows per service and
signal; UNKNOWN includes the connector command needed to make that evidence
evaluable, while MISSING can copy a starter `coverage_exceptions` YAML entry.

Version 1 YAML may also declare `coverage_expectations` and time-bounded
`coverage_exceptions`. Expectation scope supports `ALL_SERVICES`, `SERVICE`,
`NAMESPACE`, and a bounded `LABEL_SELECTOR` in `key=value` form. These policies
are persisted before the report is built, so the current scan reflects them.

## Product Boundary

The Public toolkit provides one-off audits, local history, Local UI, offline reports, Agent Skill, and MCP. Hosted scheduling, organization history, shared workflow, access control, and managed delivery remain outside the public repository.
