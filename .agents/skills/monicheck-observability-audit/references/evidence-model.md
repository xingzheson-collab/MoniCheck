# Evidence Model

MoniCheck separates facts from interpretation so an agent cannot turn incomplete topology into a confident cleanup recommendation.

## Evidence States

- `OBSERVED`: the connector directly saw the resource or relationship in the source named by the scan.
- `MISSING`: the expected resource was absent from a source that was successfully queried and whose scope is known.
- `UNKNOWN`: the source was unavailable, incomplete, ambiguous, or could not be bound to the expected scope.

Only `MISSING` can support a gap claim. `UNKNOWN` is a request for better attribution, not a negative result.

## Grafana Datasource Variables

A panel may refer to `${DS_PROMETHEUS}`, `$datasource`, or another template variable. Resolve it only when Grafana supplies a concrete current/default value that maps to a collected datasource, or when the user gives an explicit datasource UID binding.

When no unique binding exists:

- retain the panel and query as evidence;
- classify datasource attribution as `UNKNOWN`;
- exclude the panel from destructive cleanup conclusions;
- explain which binding or source evidence would make it evaluable.

Do not evaluate an ambiguous panel against every Prometheus instance. That converts deployment diversity into false missing-metric findings.

## Coverage Claims

Telemetry proves what is observed, not what should exist. Estate-wide coverage needs an independent denominator such as declared Kubernetes workloads, a service catalog, or an explicit expected-target inventory.

Use these confidence levels in prose:

- High: direct source evidence, known scope, and corroborating relationship or history.
- Medium: direct evidence with one incomplete supporting source.
- Low: inferred relationship, short observation window, or incomplete scope.
- Unknown: evidence cannot answer the question.

## Cleanup Threshold

A deletion recommendation needs all of the following:

1. unambiguous source attribution;
2. successful collection from that source;
3. absence or non-use across a meaningful observation window;
4. no contradictory dashboard, alert, recording-rule, or ownership evidence.

Without those conditions, recommend investigation or evidence collection, not deletion.
