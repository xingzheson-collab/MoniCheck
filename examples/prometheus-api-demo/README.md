# Prometheus API Demo

This fixture implements only the bounded Prometheus API responses required for
a MoniCheck product walkthrough. It is not a Prometheus replacement and its
findings do not count toward RFC-0242 customer-validation gates.

From the repository root:

```bash
make monicheck-build
make monicheck-demo-source
```

If port 19090 is already used, run
`make monicheck-demo-source MONICHECK_DEMO_ADDR=127.0.0.1:19091` and use the
same URL below.

In a second terminal:

```bash
./bin/monicheck local \
  --prometheus-url http://127.0.0.1:19090 \
  --storage-path /tmp/monicheck-demo-state.json
```

Open `http://127.0.0.1:8080/ui/static/?view=overview`. Replace the demo URL
with a read-only real Prometheus endpoint for product evaluation.

Maintainers can validate Prometheus estates that have conventional `job`
labels but no explicit `service` label with:

```bash
./bin/monicheck-prometheus-demo --listen 127.0.0.1:19092 --omit-service-label
```

MoniCheck must mark the resulting service identity as `INFERRED` from
`prometheus.job`; this fixture still does not count as customer evidence.
