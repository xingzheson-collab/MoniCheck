package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestMutableDatasourceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	readOnlyDatasource := model.Resource{
		ID:     "datasource-read-only",
		Type:   model.ResourceTypeDatasource,
		Name:   "Read Only Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceUID:      "readonly-prom",
			model.MetadataDatasourceReadOnly: "true",
		},
	}
	mutableDatasource := model.Resource{
		ID:     "datasource-mutable",
		Type:   model.ResourceTypeDatasource,
		Name:   "Mutable Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceUID:      "mutable-prom",
			model.MetadataDatasourceReadOnly: "false",
		},
	}
	unknownDatasource := model.Resource{
		ID:       "datasource-unknown",
		Type:     model.ResourceTypeDatasource,
		Name:     "Unknown Prometheus",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{},
	}
	for _, resource := range []model.Resource{readOnlyDatasource, mutableDatasource, unknownDatasource} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewMutableDatasourceAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "MutableDatasource" {
		t.Fatalf("expected MutableDatasource, got %s", findings[0].Type)
	}
	if findings[0].Resource.ID != mutableDatasource.ID {
		t.Fatalf("expected mutable datasource finding, got %s", findings[0].Resource.ID)
	}
}

func TestMutableDatasourceAnalyzerAllowlist(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	datasource := model.Resource{
		ID:     "datasource-mutable",
		Type:   model.ResourceTypeDatasource,
		Name:   "Mutable Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatasourceUID:      "mutable-prom",
			model.MetadataDatasourceReadOnly: "false",
		},
	}
	if err := store.Resources.Upsert(ctx, datasource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewMutableDatasourceAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config: map[string]any{
			"allowed_mutable_datasources": "mutable-prom",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
