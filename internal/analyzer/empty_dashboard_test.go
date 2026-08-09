package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestEmptyDashboardAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	usedDashboard := model.Resource{ID: "dashboard-used", Type: model.ResourceTypeDashboard, Name: "API Overview", Status: model.ResourceStatusActive}
	emptyDashboard := model.Resource{ID: "dashboard-empty", Type: model.ResourceTypeDashboard, Name: "Old Dashboard", Status: model.ResourceStatusActive}
	deprecatedOnlyDashboard := model.Resource{ID: "dashboard-deprecated-only", Type: model.ResourceTypeDashboard, Name: "Deprecated Panel Dashboard", Status: model.ResourceStatusActive}
	deprecatedDashboard := model.Resource{ID: "dashboard-deprecated", Type: model.ResourceTypeDashboard, Name: "Deprecated Dashboard", Status: model.ResourceStatusDeprecated}
	panel := model.Resource{ID: "panel-1", Type: model.ResourceTypePanel, Name: "Request Rate", Status: model.ResourceStatusActive}
	deprecatedPanel := model.Resource{ID: "panel-deprecated", Type: model.ResourceTypePanel, Name: "Deprecated Panel", Status: model.ResourceStatusDeprecated}

	for _, resource := range []model.Resource{usedDashboard, emptyDashboard, deprecatedOnlyDashboard, deprecatedDashboard, panel, deprecatedPanel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	relationships := []model.Relationship{
		{ID: "panel-dashboard", FromID: panel.ID, ToID: usedDashboard.ID, Type: model.RelationshipBelongsTo},
		{ID: "deprecated-panel-dashboard", FromID: deprecatedPanel.ID, ToID: deprecatedOnlyDashboard.ID, Type: model.RelationshipBelongsTo},
	}
	for _, relationship := range relationships {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewEmptyDashboardAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(findings), findings)
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
	}
	if !found[emptyDashboard.ID] || !found[deprecatedOnlyDashboard.ID] {
		t.Fatalf("expected empty dashboard findings for %s and %s, got %#v", emptyDashboard.ID, deprecatedOnlyDashboard.ID, findings)
	}
	if found[deprecatedDashboard.ID] {
		t.Fatalf("did not expect deprecated dashboard finding, got %#v", findings)
	}
}

func TestEmptyDashboardAnalyzerWithoutGraph(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	if err := store.Resources.Upsert(ctx, model.Resource{ID: "dashboard-empty", Type: model.ResourceTypeDashboard, Name: "Old Dashboard", Status: model.ResourceStatusActive}); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewEmptyDashboardAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings without graph, got %#v", findings)
	}
}
