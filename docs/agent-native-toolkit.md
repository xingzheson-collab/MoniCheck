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

## MCP Tools

- `monicheck.connectors.list`: local connector catalog.
- `monicheck.config.validate`: validates a versioned YAML configuration without exposing secret values.
- `monicheck.audit.run`: contacts only user-selected sources, persists a local baseline, and returns bounded `agent-audit.v1` aggregate evidence.

The audit result excludes credentials, endpoint URLs, resource names, labels, queries, raw evidence, dashboard JSON, source configuration, and user identity. Full owner-only reports remain local.

## Product Boundary

The Public toolkit provides one-off audits, local history, Local UI, offline reports, Agent Skill, and MCP. Hosted scheduling, organization history, shared workflow, access control, and managed delivery remain outside the public repository.
