# RFC-0328: Agent Inventory Visibility

Status: Implemented for v0.7.1

## Problem

An observed inventory does not prove that the connector could see every
folder, tenant, page, or provider object. Presenting an observed count as a
complete estate makes `MISSING` findings stronger than their evidence.

## Decision

`agent-audit.v1` and Service coverage queries include
`inventory_visibility`. The state is `NOT_PROVEN_COMPLETE` unless a future
provider-specific completeness proof exists. The contract discloses observed
resource and relationship counts, connector count, unverified dimensions, and
the basis for the state.

## Consequences

- Agents must not convert observed inventory into an estate-wide claim.
- `UNKNOWN` remains distinct from `MISSING`.
- Permission role, Grafana folder reachability, pagination, tenant, and
  organization scope remain explicit uncertainty.

## Verification

Contract tests require `NOT_PROVEN_COMPLETE` in aggregate and scoped coverage
results.
