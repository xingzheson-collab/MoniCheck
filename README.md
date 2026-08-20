# MoniCheck

MoniCheck is a local-first observability governance scanner for self-hosted and hybrid environments. It connects to Prometheus, Grafana, Alertmanager, and Kubernetes manifests, runs the built-in analyzer catalog, evaluates monitoring coverage and risk, and produces an offline report and Local UI.

This public repository is intentionally Local-only. It contains no hosted website, cloud account system, tenant control plane, Fleet management, billing, or managed execution code.

> **Release status:** `v0.6.4` is a Preview repair release. Public `v0.6.3`
> required 2h59m at roughly 3,300 resources and 39,000 relationships, while its
> receipt incorrectly measured only the analyzer window. This release batches
> durable writes, measures the complete command-to-report path, emits bounded
> progress, keeps the observed 9,461-Finding comparison exact, and leads with
> evidence completeness when source evidence is partial. The retained real
> state completes analysis and report persistence in about three seconds, but a
> fresh same-source scan is still required before the 15-minute target is
> considered real-scale validated.

## Download

Prebuilt releases cover both common CPU families. In Go release names,
`amd64` means Intel/AMD 64-bit x86 (`x86_64`), while `arm64` means 64-bit ARM.

| Operating system | CPU reported by `uname -m` | Release archive suffix |
| --- | --- | --- |
| Linux | `x86_64` | `linux_amd64.tar.gz` |
| Linux | `aarch64` or `arm64` | `linux_arm64.tar.gz` |
| macOS | `x86_64` | `darwin_amd64.tar.gz` |
| macOS | `arm64` (Apple silicon) | `darwin_arm64.tar.gz` |

Download the matching archive and `SHA256SUMS` from the
[latest GitHub Release](https://github.com/xingzheson-collab/MoniCheck/releases/latest).
Verify the checksum before running the binary.

## Quick start

```bash
go build -o monicheck ./cmd/monicheck
./monicheck local --prometheus-url http://127.0.0.1:9090
```

Open `http://127.0.0.1:8080/ui/static/`. Credentials are read from environment variables such as `MONICHECK_PROMETHEUS_BEARER_TOKEN`, `MONICHECK_GRAFANA_API_KEY`, and the corresponding `USERNAME`, `PASSWORD`, and TLS variables.

For a multi-stack scan, use the versioned YAML configuration:

```bash
export PROMETHEUS_TOKEN='...'
monicheck connectors validate --config ./monicheck.yaml
monicheck local --config ./monicheck.yaml
```

See [`examples/local-config/monicheck.example.yaml`](examples/local-config/monicheck.example.yaml). Secret values are never accepted in YAML; `auth` fields reference environment variable names. Multiple instances of the same connector type are isolated by their stable `name`.

For monitoring-gap detection, combine telemetry evidence with an independent
service inventory. A Prometheus-only scan can assess observed metrics, but
services inferred from those same metrics cannot prove estate-wide coverage.
Adding `--kubernetes-manifest` (or a Kubernetes manifest source in the YAML
configuration) lets MoniCheck compare declared workloads and Services with
observed monitoring evidence. Add Grafana and Alertmanager sources when
dashboard and alert coverage should become evaluable instead of `UNKNOWN`.
Until those independent sources are connected, use evidence completeness as
the headline result and treat evaluable coverage as a source-bounded
self-assessment.

Run `monicheck connectors list` to list supported types and telemetry groups. Local configuration supports Prometheus, Thanos, VictoriaMetrics, Mimir, Cortex, Grafana, Loki, Elasticsearch, OpenSearch, Tempo, Jaeger, SkyWalking, Pyroscope, OpenTelemetry Collector, Alertmanager, N9E, Kubernetes manifests, Datadog, and New Relic.

To try MoniCheck without an existing endpoint, start `go run ./examples/prometheus-api-demo` in another terminal and point the Local command at the demo address printed there.

After the first useful report, Local Overview exposes three explicit actions:

- download and review `activation-receipt.v1` locally;
- open the public activation feedback form;
- request a bounded Managed Pilot evaluation.

The externally reviewed validation targets and current progress are tracked in
[design-partner validation issue #1](https://github.com/xingzheson-collab/MoniCheck/issues/1).
Maintainer downloads, demo scans, fixtures, and synthetic submissions do not
count as customer evidence.

The receipt contains only aggregate report timing, counts, Coverage trust, and
build identity. It excludes credentials, endpoints, resource names, Finding
evidence, and user or machine identity. Nothing is uploaded automatically.

First-report time means command start through the durable report becoming
available. Source collection, inventory persistence, reconciliation, analysis,
Finding persistence, and report persistence are all included. Analyzer runtime
alone is not first-report time.

For CI, run a single scan:

```bash
./monicheck local --prometheus-url http://127.0.0.1:9090 --check --format json --report-out ./monicheck-report.json
```

To hand privacy-safe evidence to an optional private uploader, write the versioned bundle separately:

```bash
./monicheck local \
  --config ./monicheck.yaml \
  --check \
  --bundle-out ./monicheck-evidence.json
```

`evidence-bundle.v1` contains aggregate governance, coverage, cost, connector health, and anonymous finding/resource references. It excludes credentials, endpoint URLs, resource names, queries, raw evidence, recommendations, dashboard JSON, and source configuration. Writing a bundle does not perform network I/O; enrollment, durable upload queues, tenant identity, and managed delivery remain outside this Local repository.

## Scope

- Local connectors and deterministic analyzers
- Versioned multi-connector configuration and safe multi-instance namespacing
- Coverage and risk analysis
- Durable local snapshots and regression checks
- Offline JSON reports and loopback-only UI
- Manual privacy-safe `activation-receipt.v1` download and feedback handoff
- Privacy-safe `evidence-bundle.v1` export boundary for optional external delivery

Managed deployment and commercial services are maintained separately and are not part of this repository.

The default state path follows the operating-system user configuration
directory: `~/Library/Application Support/monicheck/local-state.json` on
macOS, `$XDG_CONFIG_HOME/monicheck/local-state.json` when configured on Linux,
and otherwise `~/.config/monicheck/local-state.json` on Linux. Use
`--storage-path` for an explicit location.
