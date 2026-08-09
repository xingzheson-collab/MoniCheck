package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestMetricNamingAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	validMetric := model.Resource{ID: "metric-valid", Type: model.ResourceTypeMetric, Name: "http_requests_total", Status: model.ResourceStatusActive}
	invalidMetric := model.Resource{ID: "metric-invalid", Type: model.ResourceTypeMetric, Name: "HTTPRequestsTotal", Status: model.ResourceStatusActive}
	deprecatedInvalidMetric := model.Resource{ID: "metric-deprecated", Type: model.ResourceTypeMetric, Name: "DeprecatedMetric", Status: model.ResourceStatusDeprecated}

	for _, resource := range []model.Resource{validMetric, invalidMetric, deprecatedInvalidMetric} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewMetricNamingAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != invalidMetric.ID {
		t.Fatalf("expected metric naming finding for %s, got %s", invalidMetric.ID, findings[0].Resource.ID)
	}
}
