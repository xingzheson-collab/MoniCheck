package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBrokenDashboardAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	healthyDashboard := model.Resource{
		ID:     "dashboard-healthy",
		Type:   model.ResourceTypeDashboard,
		Name:   "API Overview",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataHealth: "ok",
		},
	}
	brokenDashboard := model.Resource{
		ID:     "dashboard-broken",
		Type:   model.ResourceTypeDashboard,
		Name:   "Legacy Dashboard",
		Status: model.ResourceStatusBroken,
	}
	deprecatedBrokenDashboard := model.Resource{
		ID:     "dashboard-deprecated-broken",
		Type:   model.ResourceTypeDashboard,
		Name:   "Deprecated Broken Dashboard",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataHealth: "err",
		},
	}

	for _, resource := range []model.Resource{healthyDashboard, brokenDashboard, deprecatedBrokenDashboard} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewBrokenDashboardAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != brokenDashboard.ID {
		t.Fatalf("expected broken dashboard finding for %s, got %s", brokenDashboard.ID, findings[0].Resource.ID)
	}
}
