package localruntime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"monicheck/internal/connector"
	"monicheck/internal/contract"
	"monicheck/internal/model"
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

type staticConnector struct {
	id       string
	snapshot connector.Snapshot
}

func (c staticConnector) ID() string                                       { return c.id }
func (c staticConnector) Name() string                                     { return c.id }
func (c staticConnector) Sync(context.Context) (connector.Snapshot, error) { return c.snapshot, nil }

func TestNamespacedGrafanaKeepsCanonicalPrometheusMetricsExternal(t *testing.T) {
	now := time.Now().UTC()
	metricID := model.StableID("metric", "prometheus", "https://prometheus.test", "metric:http_requests_total")
	panelID := "panel-1"
	wrapped := namespaceConnector(staticConnector{id: "grafana", snapshot: connector.Snapshot{
		Resources: []model.Resource{
			{
				ID: panelID, Type: model.ResourceTypePanel, Name: "Requests", UID: panelID,
				Source: model.SourceInfo{System: "grafana", Instance: "https://grafana.test", ExternalID: "panel:1"},
				Status: model.ResourceStatusActive, CreatedAt: now, UpdatedAt: now,
			},
		},
		References: []model.Resource{{
			ID: metricID, Type: model.ResourceTypeMetric, Name: "http_requests_total", UID: metricID,
			Source: model.SourceInfo{System: "prometheus", Instance: "https://prometheus.test", ExternalID: "metric:http_requests_total"},
			Status: model.ResourceStatusActive, CreatedAt: now, UpdatedAt: now,
		}},
		Relationships: []model.Relationship{{ID: "uses", FromID: panelID, ToID: metricID, Type: model.RelationshipUses}},
		Diagnostics:   []model.Diagnostic{{ID: "grafana_prometheus_datasource_link", Status: model.ExecutionStatusSucceeded}},
	}}, "shared")
	snapshot, err := wrapped.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Resources) != 1 || snapshot.Resources[0].Type != model.ResourceTypePanel {
		t.Fatalf("Grafana snapshot overwrote canonical Prometheus Metric evidence: %#v", snapshot.Resources)
	}
	if len(snapshot.References) != 1 || snapshot.References[0].ID != metricID {
		t.Fatalf("canonical Prometheus Metric was not retained as a snapshot reference: %#v", snapshot.References)
	}
	if len(snapshot.Relationships) != 1 || snapshot.Relationships[0].ToID != metricID || snapshot.Relationships[0].FromID == panelID {
		t.Fatalf("cross-source Metric relationship was not preserved: %#v", snapshot.Relationships)
	}
	if validation := contract.ValidateSnapshot(snapshot); !validation.Valid {
		t.Fatalf("cross-source Grafana snapshot violates the connector contract: %#v", validation.Violations)
	}
}

func TestNamespacedSharedGrafanaTopologyRemainsContractComplete(t *testing.T) {
	now := time.Now().UTC()
	metricID := model.StableID("metric", "prometheus", "https://prometheus.test", "metric:node_cpu_seconds_total")
	metric := model.Resource{
		ID: metricID, Type: model.ResourceTypeMetric, Name: "node_cpu_seconds_total", UID: metricID,
		Source: model.SourceInfo{System: "prometheus", Instance: "https://prometheus.test", ExternalID: "metric:node_cpu_seconds_total"},
		Status: model.ResourceStatusActive, CreatedAt: now, UpdatedAt: now,
	}
	resources := make([]model.Resource, 0, 185)
	for index := 0; index < 39; index++ {
		id := fmt.Sprintf("datasource-%d", index)
		resources = append(resources, model.Resource{
			ID: id, Type: model.ResourceTypeDatasource, Name: id, UID: id,
			Source: model.SourceInfo{System: "grafana", Instance: "https://grafana.test", ExternalID: id},
			Status: model.ResourceStatusActive, CreatedAt: now, UpdatedAt: now,
		})
	}
	relationships := make([]model.Relationship, 0, 146)
	for index := 0; index < 146; index++ {
		id := fmt.Sprintf("panel-%d", index)
		resources = append(resources, model.Resource{
			ID: id, Type: model.ResourceTypePanel, Name: id, UID: id,
			Source: model.SourceInfo{System: "grafana", Instance: "https://grafana.test", ExternalID: id},
			Status: model.ResourceStatusActive, CreatedAt: now, UpdatedAt: now,
		})
		relationships = append(relationships, model.Relationship{
			ID: fmt.Sprintf("uses-%d", index), FromID: id, ToID: metricID, Type: model.RelationshipUses,
		})
	}

	wrapped := namespaceConnector(staticConnector{id: "grafana", snapshot: connector.Snapshot{
		Resources: resources, References: []model.Resource{metric}, Relationships: relationships,
		Diagnostics: []model.Diagnostic{{ID: "grafana_prometheus_datasource_link", Status: model.ExecutionStatusSucceeded}},
	}}, "shared-enterprise")
	snapshot, err := wrapped.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Resources) != 185 || len(snapshot.References) != 1 || len(snapshot.Relationships) != 146 {
		t.Fatalf("unexpected shared topology size: resources=%d references=%d relationships=%d", len(snapshot.Resources), len(snapshot.References), len(snapshot.Relationships))
	}
	if validation := contract.ValidateSnapshot(snapshot); !validation.Valid {
		t.Fatalf("shared Grafana topology violates the connector contract: %#v", validation.Violations)
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
		case "grafana":
			spec.Auth.APIKeyEnv = "TEST_API_KEY"
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
