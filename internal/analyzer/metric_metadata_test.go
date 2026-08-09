package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestMetricMetadataAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	completeMetric := model.Resource{
		ID:     "metric-complete",
		Type:   model.ResourceTypeMetric,
		Name:   "http_requests_total",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataMetricType: "counter",
			model.MetadataMetricHelp: "Total HTTP requests.",
			model.MetadataMetricUnit: "total",
		},
	}
	incompleteMetric := model.Resource{
		ID:     "metric-incomplete",
		Type:   model.ResourceTypeMetric,
		Name:   "legacy_queue_depth",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataMetricType: "gauge",
		},
	}
	deprecatedIncompleteMetric := model.Resource{
		ID:     "metric-deprecated-incomplete",
		Type:   model.ResourceTypeMetric,
		Name:   "legacy_queue_depth",
		Status: model.ResourceStatusDeprecated,
	}

	for _, resource := range []model.Resource{completeMetric, incompleteMetric, deprecatedIncompleteMetric} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewMetricMetadataAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	assertFindingType(t, findings, "MissingMetricHelp")
	assertFindingType(t, findings, "MissingMetricUnit")
	for _, finding := range findings {
		if finding.Type == "MissingMetricUnit" {
			assertEnglishRecommendation(t, finding)
		}
	}
}

func assertFindingType(t *testing.T, findings []model.Finding, findingType string) {
	t.Helper()

	for _, finding := range findings {
		if finding.Type == findingType {
			return
		}
	}
	t.Fatalf("expected finding type %s", findingType)
}
