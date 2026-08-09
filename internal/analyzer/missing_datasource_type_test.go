package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestMissingDatasourceTypeAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	typedDatasource := model.Resource{
		ID:     "datasource-typed",
		Type:   model.ResourceTypeDatasource,
		Name:   "Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceType: "prometheus",
			model.MetadataDatasourceURL:  "http://prometheus:9090",
		},
	}
	missingTypeDatasource := model.Resource{
		ID:     "datasource-missing-type",
		Type:   model.ResourceTypeDatasource,
		Name:   "Legacy Datasource",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceURL: "http://legacy-prometheus:9090",
		},
	}
	deprecatedMissingTypeDatasource := model.Resource{
		ID:     "datasource-deprecated-missing-type",
		Type:   model.ResourceTypeDatasource,
		Name:   "Deprecated Datasource",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataDatasourceURL: "http://deprecated-prometheus:9090",
		},
	}
	for _, resource := range []model.Resource{typedDatasource, missingTypeDatasource, deprecatedMissingTypeDatasource} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewMissingDatasourceTypeAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "MissingDatasourceType" {
		t.Fatalf("expected MissingDatasourceType, got %s", findings[0].Type)
	}
	if findings[0].Resource.ID != missingTypeDatasource.ID {
		t.Fatalf("expected missing type datasource finding, got %s", findings[0].Resource.ID)
	}
}
