package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDuplicateMetricAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	original := model.Resource{ID: "metric-a", Type: model.ResourceTypeMetric, Name: "http_requests_total", Status: model.ResourceStatusActive}
	duplicate := model.Resource{ID: "metric-b", Type: model.ResourceTypeMetric, Name: "http_requests_total", Status: model.ResourceStatusActive}
	unique := model.Resource{ID: "metric-c", Type: model.ResourceTypeMetric, Name: "node_cpu_seconds_total", Status: model.ResourceStatusActive}
	deprecatedDuplicate := model.Resource{ID: "metric-deprecated", Type: model.ResourceTypeMetric, Name: "http_requests_total", Status: model.ResourceStatusDeprecated}

	for _, resource := range []model.Resource{original, duplicate, unique, deprecatedDuplicate} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewDuplicateMetricAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != duplicate.ID {
		t.Fatalf("expected duplicate metric finding for %s, got %s", duplicate.ID, findings[0].Resource.ID)
	}
}
