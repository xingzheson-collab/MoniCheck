package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDuplicateDashboardAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	original := model.Resource{ID: "dashboard-a", Type: model.ResourceTypeDashboard, Name: "API Overview", Status: model.ResourceStatusActive}
	duplicate := model.Resource{ID: "dashboard-b", Type: model.ResourceTypeDashboard, Name: "api   overview", Status: model.ResourceStatusActive}
	unique := model.Resource{ID: "dashboard-c", Type: model.ResourceTypeDashboard, Name: "Node Overview", Status: model.ResourceStatusActive}
	deprecatedDuplicate := model.Resource{ID: "dashboard-deprecated", Type: model.ResourceTypeDashboard, Name: "API Overview", Status: model.ResourceStatusDeprecated}

	for _, resource := range []model.Resource{original, duplicate, unique, deprecatedDuplicate} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewDuplicateDashboardAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != duplicate.ID {
		t.Fatalf("expected duplicate dashboard finding for %s, got %s", duplicate.ID, findings[0].Resource.ID)
	}
}
