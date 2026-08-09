package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDashboardWithoutFolderAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	withFolder := model.Resource{
		ID:       "dashboard-with-folder",
		Type:     model.ResourceTypeDashboard,
		Name:     "API Overview",
		Source:   model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:api"},
		Metadata: map[string]string{model.MetadataFolderUID: "service-folder"},
		Status:   model.ResourceStatusActive,
	}
	withoutFolder := model.Resource{
		ID:       "dashboard-without-folder",
		Type:     model.ResourceTypeDashboard,
		Name:     "Loose Dashboard",
		Source:   model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:loose"},
		Metadata: map[string]string{model.MetadataDashboardUID: "loose"},
		Status:   model.ResourceStatusActive,
	}
	nonGrafana := model.Resource{
		ID:     "dashboard-sample",
		Type:   model.ResourceTypeDashboard,
		Name:   "Sample Dashboard",
		Source: model.SourceInfo{System: "sample", Instance: "local", ExternalID: "dashboard:sample"},
		Status: model.ResourceStatusActive,
	}
	deprecatedWithoutFolder := model.Resource{
		ID:     "dashboard-deprecated",
		Type:   model.ResourceTypeDashboard,
		Name:   "Deprecated Dashboard",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:deprecated"},
		Status: model.ResourceStatusDeprecated,
	}
	for _, resource := range []model.Resource{withFolder, withoutFolder, nonGrafana, deprecatedWithoutFolder} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewDashboardWithoutFolderAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "DashboardWithoutFolder" || findings[0].Resource.ID != withoutFolder.ID {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}
