package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBrokenTargetAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	healthyTarget := model.Resource{
		ID:     "target-healthy",
		Type:   model.ResourceTypeTarget,
		Name:   "http://10.0.0.1:9100/metrics",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataHealth: "up",
		},
	}
	brokenTarget := model.Resource{
		ID:     "target-broken",
		Type:   model.ResourceTypeTarget,
		Name:   "http://10.0.0.2:9100/metrics",
		Status: model.ResourceStatusBroken,
		Metadata: map[string]string{
			model.MetadataHealth:    "down",
			model.MetadataLastError: "connection refused",
		},
	}
	deprecatedBrokenTarget := model.Resource{
		ID:     "target-deprecated-broken",
		Type:   model.ResourceTypeTarget,
		Name:   "http://10.0.0.3:9100/metrics",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataHealth:    "down",
			model.MetadataLastError: "connection refused",
		},
	}

	for _, resource := range []model.Resource{healthyTarget, brokenTarget, deprecatedBrokenTarget} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewBrokenTargetAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != brokenTarget.ID {
		t.Fatalf("expected broken target finding for %s, got %s", brokenTarget.ID, findings[0].Resource.ID)
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", findings[0].Severity)
	}
}
