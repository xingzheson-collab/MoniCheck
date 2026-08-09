package analyzer

import (
	"context"
	"fmt"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestLargeDashboardAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	dashboard := model.Resource{ID: "dashboard-large", Type: model.ResourceTypeDashboard, Name: "Large Dashboard", Status: model.ResourceStatusActive}
	deprecatedPanelDashboard := model.Resource{ID: "dashboard-deprecated-panels", Type: model.ResourceTypeDashboard, Name: "Deprecated Panels", Status: model.ResourceStatusActive}
	deprecatedDashboard := model.Resource{ID: "dashboard-deprecated", Type: model.ResourceTypeDashboard, Name: "Deprecated Dashboard", Status: model.ResourceStatusDeprecated}
	if err := store.Resources.Upsert(ctx, dashboard); err != nil {
		t.Fatalf("upsert dashboard: %v", err)
	}
	for _, resource := range []model.Resource{deprecatedPanelDashboard, deprecatedDashboard} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert dashboard: %v", err)
		}
	}
	for i := 0; i < defaultLargeDashboardPanelThreshold+1; i++ {
		panel := model.Resource{ID: fmt.Sprintf("panel-%d", i), Type: model.ResourceTypePanel, Name: fmt.Sprintf("Panel %d", i), Status: model.ResourceStatusActive}
		if err := store.Resources.Upsert(ctx, panel); err != nil {
			t.Fatalf("upsert panel: %v", err)
		}
		if err := store.Relationships.Upsert(ctx, model.Relationship{
			ID:     fmt.Sprintf("panel-dashboard-%d", i),
			FromID: panel.ID,
			ToID:   dashboard.ID,
			Type:   model.RelationshipBelongsTo,
		}); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	for i := 0; i < defaultLargeDashboardPanelThreshold+1; i++ {
		panel := model.Resource{ID: fmt.Sprintf("deprecated-panel-%d", i), Type: model.ResourceTypePanel, Name: fmt.Sprintf("Deprecated Panel %d", i), Status: model.ResourceStatusDeprecated}
		if err := store.Resources.Upsert(ctx, panel); err != nil {
			t.Fatalf("upsert deprecated panel: %v", err)
		}
		if err := store.Relationships.Upsert(ctx, model.Relationship{
			ID:     fmt.Sprintf("deprecated-panel-dashboard-%d", i),
			FromID: panel.ID,
			ToID:   deprecatedPanelDashboard.ID,
			Type:   model.RelationshipBelongsTo,
		}); err != nil {
			t.Fatalf("upsert deprecated panel relationship: %v", err)
		}
	}
	for i := 0; i < defaultLargeDashboardPanelThreshold+1; i++ {
		panel := model.Resource{ID: fmt.Sprintf("deprecated-dashboard-panel-%d", i), Type: model.ResourceTypePanel, Name: fmt.Sprintf("Deprecated Dashboard Panel %d", i), Status: model.ResourceStatusActive}
		if err := store.Resources.Upsert(ctx, panel); err != nil {
			t.Fatalf("upsert deprecated dashboard panel: %v", err)
		}
		if err := store.Relationships.Upsert(ctx, model.Relationship{
			ID:     fmt.Sprintf("deprecated-dashboard-panel-dashboard-%d", i),
			FromID: panel.ID,
			ToID:   deprecatedDashboard.ID,
			Type:   model.RelationshipBelongsTo,
		}); err != nil {
			t.Fatalf("upsert deprecated dashboard panel relationship: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewLargeDashboardAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != dashboard.ID {
		t.Fatalf("expected large dashboard finding for %s, got %s", dashboard.ID, findings[0].Resource.ID)
	}
	if findings[0].Metadata["panel_count"] != fmt.Sprintf("%d", defaultLargeDashboardPanelThreshold+1) {
		t.Fatalf("expected panel count metadata, got %#v", findings[0].Metadata)
	}
}

func TestLargeDashboardAnalyzerWithoutGraph(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	if err := store.Resources.Upsert(ctx, model.Resource{ID: "dashboard-large", Type: model.ResourceTypeDashboard, Name: "Large Dashboard", Status: model.ResourceStatusActive}); err != nil {
		t.Fatalf("upsert dashboard: %v", err)
	}

	findings, err := NewLargeDashboardAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings without graph, got %#v", findings)
	}
}
