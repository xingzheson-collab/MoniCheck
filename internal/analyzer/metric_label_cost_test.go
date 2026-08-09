package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestMetricLabelCostAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{ID: "label-job", Type: model.ResourceTypeMetricLabel, Name: "job", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataMetricLabelValueCount: "10", model.MetadataMetricLabelMemoryBytes: "100"}},
		{ID: "label-user", Type: model.ResourceTypeMetricLabel, Name: "user_id", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataMetricLabelValueCount: "5000", model.MetadataMetricLabelMemoryBytes: "2000000", model.MetadataMetricLabelTopValue: "customer-1", model.MetadataMetricLabelTopSeries: "1200"}},
		{ID: "label-old", Type: model.ResourceTypeMetricLabel, Name: "request_id", Status: model.ResourceStatusDeprecated, Metadata: map[string]string{model.MetadataMetricLabelValueCount: "9000", model.MetadataMetricLabelMemoryBytes: "9000000"}},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	cardinalityFindings, err := NewHighCardinalityMetricLabelAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute cardinality analyzer: %v", err)
	}
	if len(cardinalityFindings) != 1 || cardinalityFindings[0].Resource.ID != "label-user" || cardinalityFindings[0].Metadata[model.MetadataMetricLabelTopValue] != "customer-1" {
		t.Fatalf("expected one high-cardinality label finding, got %#v", cardinalityFindings)
	}

	memoryFindings, err := NewHighMemoryMetricLabelAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute memory analyzer: %v", err)
	}
	if len(memoryFindings) != 1 || memoryFindings[0].Resource.ID != "label-user" || memoryFindings[0].Metadata["memory_bytes"] != "2000000" {
		t.Fatalf("expected one high-memory label finding, got %#v", memoryFindings)
	}
}

func TestMetricLabelCostAnalyzersCustomThresholds(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := model.Resource{ID: "label-route", Type: model.ResourceTypeMetricLabel, Name: "route", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataMetricLabelValueCount: "50", model.MetadataMetricLabelMemoryBytes: "500"}}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	cardinalityFindings, err := NewHighCardinalityMetricLabelAnalyzer().Execute(ctx, Context{Resources: store.Resources, Config: map[string]any{"metric_label_value_threshold": 40}})
	if err != nil || len(cardinalityFindings) != 1 {
		t.Fatalf("expected custom cardinality threshold finding, findings=%#v err=%v", cardinalityFindings, err)
	}
	memoryFindings, err := NewHighMemoryMetricLabelAnalyzer().Execute(ctx, Context{Resources: store.Resources, Config: map[string]any{"metric_label_memory_bytes_threshold": 400}})
	if err != nil || len(memoryFindings) != 1 {
		t.Fatalf("expected custom memory threshold finding, findings=%#v err=%v", memoryFindings, err)
	}
}
