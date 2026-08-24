# RFC-0337: Bound Inventory Identity

- Status: Implemented for v0.7.5
- Scope: Local connector namespaces, Grafana-to-Prometheus references, exact failure evidence

## Problem

v0.7.4 introduced exact broken-reference findings but joined Grafana references
to Prometheus inventory through two implicit assumptions. The Local runtime
namespaced observed Prometheus resources while Grafana retained the pre-namespace
ID. URL redaction could also change a synthetic metric's source instance before
the connector decided whether it was an external reference or observed inventory.

Those assumptions produced opposite failures in two valid deployments:

- an explicit datasource UID with an internal Grafana URL could report a
  collected metric as absent (P29);
- a Grafana datasource URL equal to the scanned Prometheus URL could persist a
  synthetic missing metric as observed inventory and suppress the finding (P30).

## Decision

Exact cross-source evidence now has two explicit identities:

1. the configured Prometheus metric instance; and
2. the target Local connector ID that owns the inventory.

Grafana builds the metric reference with the same namespaced resource ID that
the bound Prometheus connector persists. The Local namespace function is a
shared model contract rather than duplicated string construction.

Reference membership is derived from the `EXACT` relationship before URL
sanitization. Redaction may change a displayed source fingerprint, but it cannot
turn a reference placeholder into observed inventory or change its resource ID.

## Evidence boundary

- A reference is exact only after datasource attribution and connector binding
  both succeed.
- A Grafana query never creates observed Prometheus inventory. Only the bound
  Prometheus connector can prove metric membership.
- Internal and external URLs may differ when an explicit datasource UID binds
  them; URL equality is neither required nor sufficient after that binding.
- Variables, unresolved datasource references, missing inventories, and partial
  visibility remain unproven.

## Acceptance

- With an explicit UID binding and different internal/external URLs, a collected
  `up` metric produces no missing-metric finding.
- In the same topology, an absent panel metric and absent alert metric remain
  dangling exact references and produce their expected findings.
- When Grafana and the scanned Prometheus use the same URL, absent query metrics
  remain references and cannot be persisted as observed inventory.
- Local connector namespacing joins the Grafana target ID to the exact resource
  ID persisted by the bound Prometheus connector.
- Existing variable and unknown paths do not gain `EXACT` evidence.

## Regression discipline

Any future CRITICAL cross-connector analyzer must test identity joining with
different URLs, equal URLs, multiple connector namespaces, and a known-present
plus known-absent control pair. Sanitized presentation fields cannot be used as
identity authorities.
