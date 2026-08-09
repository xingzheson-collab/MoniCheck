package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDuplicateRecordingRuleOutputAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	original := model.Resource{
		ID:     "recording-a",
		Type:   model.ResourceTypeRecordingRule,
		Name:   "job:http_requests:rate5m",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataRecordingRuleOutput: "job:http_requests:rate5m",
		},
	}
	duplicate := model.Resource{
		ID:     "recording-b",
		Type:   model.ResourceTypeRecordingRule,
		Name:   "job:http_requests:rate5m",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataRecordingRuleOutput: "job:http_requests:rate5m",
		},
	}
	unique := model.Resource{
		ID:     "recording-c",
		Type:   model.ResourceTypeRecordingRule,
		Name:   "job:latency:p95",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataRecordingRuleOutput: "job:latency:p95",
		},
	}
	inactiveDuplicate := model.Resource{
		ID:     "recording-disabled",
		Type:   model.ResourceTypeRecordingRule,
		Name:   "job:http_requests:rate5m",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataRecordingRuleOutput: "job:http_requests:rate5m",
		},
	}
	for _, resource := range []model.Resource{original, duplicate, unique, inactiveDuplicate} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewDuplicateRecordingRuleOutputAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != duplicate.ID {
		t.Fatalf("expected duplicate recording output finding for %s, got %s", duplicate.ID, findings[0].Resource.ID)
	}
	if findings[0].Metadata["output_metric"] != "job:http_requests:rate5m" {
		t.Fatalf("expected output metric metadata, got %#v", findings[0].Metadata)
	}
}

func TestDuplicateRecordingRuleOutputAnalyzerFallsBackToName(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		{ID: "recording-a", Type: model.ResourceTypeRecordingRule, Name: "job:http_requests:rate5m", Status: model.ResourceStatusActive, Metadata: map[string]string{}},
		{ID: "recording-b", Type: model.ResourceTypeRecordingRule, Name: "job:http_requests:rate5m", Status: model.ResourceStatusActive, Metadata: map[string]string{}},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewDuplicateRecordingRuleOutputAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding with name fallback, got %d", len(findings))
	}
}
