package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestInvalidDatasourceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	validDatasource := model.Resource{
		ID:     "datasource-valid",
		Type:   model.ResourceTypeDatasource,
		Name:   "Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceURL: "http://prometheus:9090",
		},
	}
	invalidDatasource := model.Resource{
		ID:     "datasource-invalid",
		Type:   model.ResourceTypeDatasource,
		Name:   "Broken Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceURLConfigured: "true",
			model.MetadataDatasourceURLValid:      "false",
		},
	}
	deprecatedInvalidDatasource := model.Resource{
		ID:     "datasource-deprecated-invalid",
		Type:   model.ResourceTypeDatasource,
		Name:   "Deprecated Broken Prometheus",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataDatasourceURL: "://missing-scheme",
			model.MetadataHealth:        "err",
		},
	}

	for _, resource := range []model.Resource{validDatasource, invalidDatasource, deprecatedInvalidDatasource} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewInvalidDatasourceAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != invalidDatasource.ID {
		t.Fatalf("expected invalid datasource finding for %s, got %s", invalidDatasource.ID, findings[0].Resource.ID)
	}
}
