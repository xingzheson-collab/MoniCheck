package localruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"monicheck/internal/connector"
)

func TestLoadAndValidateMultiConnectorConfig(t *testing.T) {
	t.Setenv("PROM_TOKEN", "secret")
	path := writeConfig(t, `version: 1
connectors:
  - type: prometheus
    name: production
    url: https://prometheus.example
    auth:
      bearer_token_env: PROM_TOKEN
  - type: loki
    name: logs
    url: https://loki.example
    tenant_id: tenant-a
`)
	cfg, err := ValidateFileConfig(path)
	if err != nil {
		t.Fatalf("validate config: %v", err)
	}
	if len(cfg.Connectors) != 2 {
		t.Fatalf("connector count = %d", len(cfg.Connectors))
	}
	connectors, err := buildConfiguredConnectors(cfg)
	if err != nil {
		t.Fatalf("build connectors: %v", err)
	}
	if connectors[0].ID() != "prometheus:production" || connectors[1].ID() != "loki:logs" {
		t.Fatalf("unexpected IDs: %s, %s", connectors[0].ID(), connectors[1].ID())
	}
}

func TestConfigRejectsUnknownFieldsAndMissingSecrets(t *testing.T) {
	unknown := writeConfig(t, "version: 1\nconnectors:\n  - type: prometheus\n    url: http://prometheus\n    token: literal-secret\n")
	if _, err := LoadFileConfig(unknown); err == nil || !strings.Contains(err.Error(), "field token not found") {
		t.Fatalf("unexpected unknown-field error: %v", err)
	}
	missing := writeConfig(t, "version: 1\nconnectors:\n  - type: datadog\n    url: https://api.datadoghq.com\n    auth:\n      api_key_env: MISSING_DATADOG_KEY\n")
	if _, err := ValidateFileConfig(missing); err == nil || !strings.Contains(err.Error(), "MISSING_DATADOG_KEY is not set") {
		t.Fatalf("unexpected secret error: %v", err)
	}
}

func TestNamespacedConnectorRewritesResourceGraph(t *testing.T) {
	wrapped := namespaceConnector(connector.NewSampleConnector(), "second cluster")
	snapshot, err := wrapped.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Resources) == 0 {
		t.Fatal("sample connector returned no resources")
	}
	for _, resource := range snapshot.Resources {
		if resource.Source.Cluster != "sample:second-cluster" {
			t.Fatalf("cluster namespace = %q", resource.Source.Cluster)
		}
	}
	for _, relation := range snapshot.Relationships {
		if relation.FromID == "" || relation.ToID == "" {
			t.Fatalf("invalid relation: %#v", relation)
		}
	}
}

func TestEveryCatalogConnectorBuilds(t *testing.T) {
	t.Setenv("TEST_API_KEY", "api-key")
	t.Setenv("TEST_APP_KEY", "application-key")
	t.Setenv("TEST_USER_KEY", "user-key")
	manifest := filepath.Join(t.TempDir(), "service.yaml")
	if err := os.WriteFile(manifest, []byte("apiVersion: v1\nkind: Service\nmetadata:\n  name: checkout\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	otel := filepath.Join(t.TempDir(), "otelcol.yaml")
	if err := os.WriteFile(otel, []byte("receivers:\n  otlp:\n    protocols:\n      grpc:\nexporters:\n  debug: {}\nservice:\n  pipelines:\n    traces:\n      receivers: [otlp]\n      exporters: [debug]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, item := range ConnectorCatalog() {
		spec := ConnectorSpec{Type: item.Type, Name: item.Type, URL: "https://example.com"}
		switch item.Type {
		case "datadog":
			spec.Auth.APIKeyEnv, spec.Auth.ApplicationKeyEnv = "TEST_API_KEY", "TEST_APP_KEY"
		case "newrelic":
			spec.AccountID, spec.Auth.UserKeyEnv = 1234, "TEST_USER_KEY"
		case "otelcol":
			spec.Path = otel
		case "kubernetes":
			spec.Path = manifest
		}
		if _, err := buildConnector(spec); err != nil {
			t.Errorf("%s connector: %v", item.Type, err)
		}
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "monicheck.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
