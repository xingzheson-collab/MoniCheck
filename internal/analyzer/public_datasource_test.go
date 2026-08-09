package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPublicDatasourceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	internalDatasource := model.Resource{
		ID:       "datasource-internal",
		Type:     model.ResourceTypeDatasource,
		Name:     "Internal Prometheus",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataDatasourceURL: "http://prometheus:9090"},
	}
	privateIPDatasource := model.Resource{
		ID:       "datasource-private-ip",
		Type:     model.ResourceTypeDatasource,
		Name:     "Private Prometheus",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataDatasourceURL: "http://10.0.0.12:9090"},
	}
	publicDatasource := model.Resource{
		ID:     "datasource-public",
		Type:   model.ResourceTypeDatasource,
		Name:   "Public Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceURLConfigured:       "true",
			model.MetadataDatasourceURLValid:            "true",
			model.MetadataDatasourceURLScheme:           "https",
			model.MetadataDatasourceURLHostScope:        "public",
			model.MetadataDatasourceURLHostFingerprint:  datasourceHostFingerprint("prometheus.example.com"),
			model.MetadataDatasourceEndpointFingerprint: model.StableID("datasource-endpoint", "https://prometheus.example.com"),
		},
	}
	allowedDatasource := model.Resource{
		ID:     "datasource-allowed",
		Type:   model.ResourceTypeDatasource,
		Name:   "Allowed Public Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceURLConfigured:      "true",
			model.MetadataDatasourceURLValid:           "true",
			model.MetadataDatasourceURLScheme:          "https",
			model.MetadataDatasourceURLHostScope:       "public",
			model.MetadataDatasourceURLHostFingerprint: datasourceHostFingerprint("metrics.example.com"),
		},
	}
	deprecatedPublicDatasource := model.Resource{
		ID:       "datasource-deprecated-public",
		Type:     model.ResourceTypeDatasource,
		Name:     "Deprecated Public Prometheus",
		Status:   model.ResourceStatusDeprecated,
		Metadata: map[string]string{model.MetadataDatasourceURL: "https://deprecated.example.com"},
	}
	for _, resource := range []model.Resource{internalDatasource, privateIPDatasource, publicDatasource, allowedDatasource, deprecatedPublicDatasource} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewPublicDatasourceAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"allowed_public_datasource_hosts": "metrics.example.com"},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "PublicDatasource" || findings[0].Resource.ID != publicDatasource.ID {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if strings.Contains(strings.Join(findings[0].Evidence, " "), "prometheus.example.com") {
		t.Fatalf("finding evidence must not disclose the datasource hostname: %#v", findings[0].Evidence)
	}
}
