package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDashboardWithoutTagsAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	withTags := model.Resource{
		ID:     "dashboard-with-tags",
		Type:   model.ResourceTypeDashboard,
		Name:   "API Overview",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:api"},
		Metadata: map[string]string{
			model.MetadataDashboardTags: "api,prod",
		},
	}
	withoutTags := model.Resource{
		ID:       "dashboard-without-tags",
		Type:     model.ResourceTypeDashboard,
		Name:     "Loose Dashboard",
		Status:   model.ResourceStatusActive,
		Source:   model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:loose"},
		Metadata: map[string]string{},
	}
	sampleDashboard := model.Resource{
		ID:       "dashboard-sample",
		Type:     model.ResourceTypeDashboard,
		Name:     "Sample Dashboard",
		Status:   model.ResourceStatusActive,
		Source:   model.SourceInfo{System: "sample", Instance: "local", ExternalID: "dashboard:sample"},
		Metadata: map[string]string{},
	}
	deprecatedWithoutTags := model.Resource{
		ID:       "dashboard-deprecated",
		Type:     model.ResourceTypeDashboard,
		Name:     "Deprecated Dashboard",
		Status:   model.ResourceStatusDeprecated,
		Source:   model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:deprecated"},
		Metadata: map[string]string{},
	}
	for _, resource := range []model.Resource{withTags, withoutTags, sampleDashboard, deprecatedWithoutTags} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewDashboardWithoutTagsAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "DashboardWithoutTags" {
		t.Fatalf("expected DashboardWithoutTags, got %s", findings[0].Type)
	}
	if findings[0].Resource.ID != withoutTags.ID {
		t.Fatalf("expected dashboard without tags finding, got %s", findings[0].Resource.ID)
	}
}
