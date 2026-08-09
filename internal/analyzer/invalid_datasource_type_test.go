package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestInvalidDatasourceTypeAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	validDatasource := model.Resource{
		ID:     "datasource-valid",
		Type:   model.ResourceTypeDatasource,
		Name:   "Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceType: "prometheus",
		},
	}
	missingTypeDatasource := model.Resource{
		ID:       "datasource-missing-type",
		Type:     model.ResourceTypeDatasource,
		Name:     "Missing Type",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{},
	}
	invalidDatasource := model.Resource{
		ID:     "datasource-invalid",
		Type:   model.ResourceTypeDatasource,
		Name:   "Unknown Datasource",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceType: "homegrown",
		},
	}
	for _, resource := range []model.Resource{validDatasource, missingTypeDatasource, invalidDatasource} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewInvalidDatasourceTypeAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "InvalidDatasourceType" {
		t.Fatalf("expected InvalidDatasourceType, got %s", findings[0].Type)
	}
	if findings[0].Resource.ID != invalidDatasource.ID {
		t.Fatalf("expected invalid datasource type finding, got %s", findings[0].Resource.ID)
	}
}

func TestInvalidDatasourceTypeAnalyzerConfiguredTypes(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	datasource := model.Resource{
		ID:     "datasource-custom",
		Type:   model.ResourceTypeDatasource,
		Name:   "Custom Datasource",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceType: "homegrown",
		},
	}
	if err := store.Resources.Upsert(ctx, datasource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewInvalidDatasourceTypeAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config: map[string]any{
			"allowed_datasource_types": "prometheus,homegrown",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
