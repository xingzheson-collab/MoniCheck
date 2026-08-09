package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestHighCardinalityMetricAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	normalMetric := model.Resource{
		ID:     "metric-normal",
		Type:   model.ResourceTypeMetric,
		Name:   "http_requests_total",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataSeriesCount: "10",
		},
	}
	largeMetric := model.Resource{
		ID:     "metric-large",
		Type:   model.ResourceTypeMetric,
		Name:   "container_cpu_usage_seconds_total",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataSeriesCount:         "1200",
			model.MetadataSeriesCountSource:   "tsdb_head",
			model.MetadataTSDBHeadSeriesCount: "1200",
			model.MetadataRecentSeriesCount:   "900",
		},
	}
	deprecatedLargeMetric := model.Resource{
		ID:     "metric-deprecated-large",
		Type:   model.ResourceTypeMetric,
		Name:   "legacy_container_cpu_usage_seconds_total",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataSeriesCount: "5000",
		},
	}

	for _, resource := range []model.Resource{normalMetric, largeMetric, deprecatedLargeMetric} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewHighCardinalityMetricAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != largeMetric.ID {
		t.Fatalf("expected high cardinality finding for %s, got %s", largeMetric.ID, findings[0].Resource.ID)
	}
	assertEnglishRecommendation(t, findings[0])
	if findings[0].Metadata[model.MetadataSeriesCountSource] != "tsdb_head" ||
		findings[0].Metadata[model.MetadataTSDBHeadSeriesCount] != "1200" ||
		findings[0].Metadata[model.MetadataRecentSeriesCount] != "900" {
		t.Fatalf("expected cardinality evidence sources, got %#v", findings[0].Metadata)
	}
}
