package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestFastDashboardRefreshAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	normalDashboard := model.Resource{
		ID:     "dashboard-normal",
		Type:   model.ResourceTypeDashboard,
		Name:   "Normal Dashboard",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:normal"},
		Metadata: map[string]string{
			model.MetadataDashboardRefresh: "1m",
		},
	}
	fastDashboard := model.Resource{
		ID:     "dashboard-fast",
		Type:   model.ResourceTypeDashboard,
		Name:   "Fast Dashboard",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:fast"},
		Metadata: map[string]string{
			model.MetadataDashboardRefresh: "5s",
		},
	}
	offDashboard := model.Resource{
		ID:     "dashboard-off",
		Type:   model.ResourceTypeDashboard,
		Name:   "Off Dashboard",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:off"},
		Metadata: map[string]string{
			model.MetadataDashboardRefresh: "off",
		},
	}
	sampleDashboard := model.Resource{
		ID:     "dashboard-sample",
		Type:   model.ResourceTypeDashboard,
		Name:   "Sample Dashboard",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "sample", Instance: "local", ExternalID: "dashboard:sample"},
		Metadata: map[string]string{
			model.MetadataDashboardRefresh: "5s",
		},
	}
	deprecatedDashboard := model.Resource{
		ID:     "dashboard-deprecated-fast",
		Type:   model.ResourceTypeDashboard,
		Name:   "Deprecated Fast Dashboard",
		Status: model.ResourceStatusDeprecated,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:deprecated-fast"},
		Metadata: map[string]string{
			model.MetadataDashboardRefresh: "5s",
		},
	}
	for _, resource := range []model.Resource{normalDashboard, fastDashboard, offDashboard, sampleDashboard, deprecatedDashboard} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewFastDashboardRefreshAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "FastDashboardRefresh" {
		t.Fatalf("expected FastDashboardRefresh, got %s", findings[0].Type)
	}
	if findings[0].Resource.ID != fastDashboard.ID {
		t.Fatalf("expected fast dashboard finding, got %s", findings[0].Resource.ID)
	}
}

func TestFastDashboardRefreshAnalyzerConfiguredThreshold(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	dashboard := model.Resource{
		ID:     "dashboard",
		Type:   model.ResourceTypeDashboard,
		Name:   "Dashboard",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard"},
		Metadata: map[string]string{
			model.MetadataDashboardRefresh: "20s",
		},
	}
	if err := store.Resources.Upsert(ctx, dashboard); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewFastDashboardRefreshAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config: map[string]any{
			"fast_dashboard_refresh_threshold": "10s",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
