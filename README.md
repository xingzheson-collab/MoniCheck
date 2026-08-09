# MoniCheck

MoniCheck is a local-first observability governance scanner for self-hosted and hybrid environments. It connects to Prometheus, Grafana, Alertmanager, and Kubernetes manifests, runs the built-in analyzer catalog, evaluates monitoring coverage and risk, and produces an offline report and Local UI.

This public repository is intentionally Local-only. It contains no hosted website, cloud account system, tenant control plane, Fleet management, billing, or managed execution code.

## Quick start

```bash
go build -o monicheck ./cmd/monicheck
./monicheck local --prometheus-url http://127.0.0.1:9090
```

Open `http://127.0.0.1:8080/ui/static/`. Credentials are read from environment variables such as `MONICHECK_PROMETHEUS_BEARER_TOKEN`, `MONICHECK_GRAFANA_API_KEY`, and the corresponding `USERNAME`, `PASSWORD`, and TLS variables.

To try MoniCheck without an existing endpoint, start `go run ./examples/prometheus-api-demo` in another terminal and point the Local command at the demo address printed there.

For CI, run a single scan:

```bash
./monicheck local --prometheus-url http://127.0.0.1:9090 --check --format json --report-out ./monicheck-report.json
```

## Scope

- Local connectors and deterministic analyzers
- Coverage and risk analysis
- Durable local snapshots and regression checks
- Offline JSON reports and loopback-only UI

Managed deployment and commercial services are maintained separately and are not part of this repository.
