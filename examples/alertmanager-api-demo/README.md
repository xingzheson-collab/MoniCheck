# Alertmanager API Demo

This loopback fixture exercises MoniCheck's Alertmanager v2 API discovery and
private-ingress authentication. It is test data only and never counts as a real
customer activation receipt or product evidence.

```bash
MONICHECK_DEMO_BASIC_AUTH_USERNAME=reader \
MONICHECK_DEMO_BASIC_AUTH_PASSWORD=private-password \
go run ./examples/alertmanager-api-demo --listen 127.0.0.1:19095
```
