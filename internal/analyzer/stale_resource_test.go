package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestStaleResourceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	freshMetric := model.Resource{
		ID:     "metric-fresh",
		Type:   model.ResourceTypeMetric,
		Name:   "http_requests_total",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataLastUsedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		},
	}
	staleDashboard := model.Resource{
		ID:     "dashboard-stale",
		Type:   model.ResourceTypeDashboard,
		Name:   "Legacy Dashboard",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataLastUsedAt: time.Now().UTC().Add(-defaultStaleResourceThreshold - time.Hour).Format(time.RFC3339),
		},
	}

	for _, resource := range []model.Resource{freshMetric, staleDashboard} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewStaleResourceAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != staleDashboard.ID {
		t.Fatalf("expected stale resource finding for %s, got %s", staleDashboard.ID, findings[0].Resource.ID)
	}
}
