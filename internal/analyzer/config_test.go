package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestAnalyzerConfigThresholds(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	metric := model.Resource{
		ID:     "metric-1",
		Type:   model.ResourceTypeMetric,
		Name:   "http_requests_total",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataSeriesCount: "600",
		},
	}
	if err := store.Resources.Upsert(ctx, metric); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	defaultFindings, err := NewHighCardinalityMetricAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute default analyzer: %v", err)
	}
	if len(defaultFindings) != 0 {
		t.Fatalf("expected no finding with default threshold, got %d", len(defaultFindings))
	}

	configuredFindings, err := NewHighCardinalityMetricAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"series_count_threshold": 500},
	})
	if err != nil {
		t.Fatalf("execute configured analyzer: %v", err)
	}
	if len(configuredFindings) != 1 {
		t.Fatalf("expected 1 finding with configured threshold, got %d", len(configuredFindings))
	}
}
