package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestEditableDashboardAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	lockedDashboard := model.Resource{
		ID:     "dashboard-locked",
		Type:   model.ResourceTypeDashboard,
		Name:   "Locked Dashboard",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:locked"},
		Metadata: map[string]string{
			model.MetadataDashboardUID:      "locked",
			model.MetadataDashboardEditable: "false",
		},
	}
	editableDashboard := model.Resource{
		ID:     "dashboard-editable",
		Type:   model.ResourceTypeDashboard,
		Name:   "Editable Dashboard",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:editable"},
		Metadata: map[string]string{
			model.MetadataDashboardUID:      "editable",
			model.MetadataDashboardEditable: "true",
		},
	}
	unknownDashboard := model.Resource{
		ID:       "dashboard-unknown",
		Type:     model.ResourceTypeDashboard,
		Name:     "Unknown Dashboard",
		Status:   model.ResourceStatusActive,
		Source:   model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:unknown"},
		Metadata: map[string]string{},
	}
	sampleDashboard := model.Resource{
		ID:     "dashboard-sample",
		Type:   model.ResourceTypeDashboard,
		Name:   "Sample Dashboard",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "sample", Instance: "local", ExternalID: "dashboard:sample"},
		Metadata: map[string]string{
			model.MetadataDashboardEditable: "true",
		},
	}
	deprecatedEditableDashboard := model.Resource{
		ID:     "dashboard-deprecated",
		Type:   model.ResourceTypeDashboard,
		Name:   "Deprecated Editable Dashboard",
		Status: model.ResourceStatusDeprecated,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:deprecated"},
		Metadata: map[string]string{
			model.MetadataDashboardEditable: "true",
		},
	}
	for _, resource := range []model.Resource{lockedDashboard, editableDashboard, unknownDashboard, sampleDashboard, deprecatedEditableDashboard} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewEditableDashboardAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "EditableDashboard" {
		t.Fatalf("expected EditableDashboard, got %s", findings[0].Type)
	}
	if findings[0].Resource.ID != editableDashboard.ID {
		t.Fatalf("expected editable dashboard finding, got %s", findings[0].Resource.ID)
	}
}

func TestEditableDashboardAnalyzerAllowlist(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	dashboard := model.Resource{
		ID:     "dashboard-editable",
		Type:   model.ResourceTypeDashboard,
		Name:   "Editable Dashboard",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:editable"},
		Metadata: map[string]string{
			model.MetadataDashboardUID:      "editable",
			model.MetadataDashboardEditable: "true",
		},
	}
	if err := store.Resources.Upsert(ctx, dashboard); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewEditableDashboardAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config: map[string]any{
			"allowed_editable_dashboards": "editable",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
