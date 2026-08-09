package analyzer

import (
	"context"
	"strings"
	"testing"
	"unicode"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestMetricCostAttributionAnalyzersReportRequiredMissingAndConflictingDimensions(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{
			ID: "missing", Type: model.ResourceTypeMetric, Name: "missing", Status: model.ResourceStatusActive,
			Labels:   map[string]string{"team": "payments"},
			Metadata: map[string]string{model.MetadataSeriesCount: "5000", model.MetadataSeriesCountSource: "tsdb_head"},
		},
		{
			ID: "conflict", Type: model.ResourceTypeMetric, Name: "conflict", Status: model.ResourceStatusActive,
			Labels:   map[string]string{"team": "payments", "project": "commerce"},
			Metadata: map[string]string{"project": "growth", model.MetadataSeriesCount: "3000", model.MetadataSeriesCountSource: "recent_1h"},
		},
		{
			ID: "unmeasured", Type: model.ResourceTypeMetric, Name: "unmeasured", Status: model.ResourceStatusActive,
		},
		{
			ID: "orphan", Type: model.ResourceTypeMetric, Name: "orphan", Status: model.ResourceStatusOrphan,
			Metadata: map[string]string{model.MetadataSeriesCount: "9000"},
		},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	analysis := Context{
		Resources: store.Resources,
		Config: map[string]any{
			"cost_allocation_required_dimensions": []string{"team", "project"},
		},
	}

	missing, err := NewUnallocatedMetricCostAnalyzer().Execute(ctx, analysis)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0].Resource.ID != "missing" || missing[0].Metadata["allocation_dimension"] != "project" {
		t.Fatalf("unexpected missing attribution findings %#v", missing)
	}
	if missing[0].Metadata["series_count"] != "5000" || missing[0].Category != "" {
		t.Fatalf("expected bounded native-series evidence %#v", missing[0])
	}
	assertEnglishRecommendation(t, missing[0])
	conflicting, err := NewAmbiguousMetricCostAllocationAnalyzer().Execute(ctx, analysis)
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicting) != 1 || conflicting[0].Resource.ID != "conflict" ||
		conflicting[0].Metadata["allocation_dimension"] != "project" ||
		conflicting[0].Metadata["allocation_value_count"] != "2" {
		t.Fatalf("unexpected ambiguous attribution findings %#v", conflicting)
	}
	for _, evidence := range conflicting[0].Evidence {
		if strings.Contains(evidence, "commerce") || strings.Contains(evidence, "growth") {
			t.Fatalf("attribution values must not be copied into evidence: %#v", conflicting[0])
		}
	}
	assertEnglishRecommendation(t, conflicting[0])
}

func assertEnglishRecommendation(t *testing.T, finding model.Finding) {
	t.Helper()
	if strings.TrimSpace(finding.Recommendation) == "" {
		t.Fatalf("finding %s must have a recommendation", finding.Type)
	}
	for _, r := range finding.Recommendation {
		if unicode.Is(unicode.Han, r) {
			t.Fatalf("finding %s recommendation must be English: %q", finding.Type, finding.Recommendation)
		}
	}
}

func TestCostAllocationRequiredDimensionsRejectsUnsupportedConfig(t *testing.T) {
	dimensions := costAllocationRequiredDimensions(map[string]any{
		"cost_allocation_required_dimensions": "unknown,service,team,service",
	})
	if len(dimensions) != 2 || dimensions[0] != "service" || dimensions[1] != "team" {
		t.Fatalf("unexpected normalized dimensions %#v", dimensions)
	}
	if fallback := costAllocationRequiredDimensions(map[string]any{
		"cost_allocation_required_dimensions": "unknown",
	}); len(fallback) != 1 || fallback[0] != "team" {
		t.Fatalf("expected team fallback, got %#v", fallback)
	}
}
