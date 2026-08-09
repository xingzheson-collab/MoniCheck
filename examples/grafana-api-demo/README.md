# Grafana API demo

This loopback-only fixture validates MoniCheck installation and Grafana
private-ingress behavior. It is not customer evidence for RFC-0242.

```bash
MONICHECK_DEMO_BASIC_AUTH_USERNAME=reader \
MONICHECK_DEMO_BASIC_AUTH_PASSWORD=private-password \
go run ./examples/grafana-api-demo --listen 127.0.0.1:19094
```

Connect with `MONICHECK_GRAFANA_USERNAME`, `MONICHECK_GRAFANA_PASSWORD`, and
`monicheck local --grafana-url http://127.0.0.1:19094`.
