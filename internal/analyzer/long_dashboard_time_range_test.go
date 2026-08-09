package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestLongDashboardTimeRangeAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	normalDashboard := model.Resource{
		ID:     "dashboard-normal",
		Type:   model.ResourceTypeDashboard,
		Name:   "API",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:api"},
		Metadata: map[string]string{
			model.MetadataDashboardTimeRange: "6h0m0s",
		},
		Status: model.ResourceStatusActive,
	}
	longDashboard := model.Resource{
		ID:     "dashboard-long",
		Type:   model.ResourceTypeDashboard,
		Name:   "Long Window",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:long"},
		Metadata: map[string]string{
			model.MetadataDashboardUID:       "long",
			model.MetadataDashboardTimeRange: "336h0m0s",
		},
		Status: model.ResourceStatusActive,
	}
	unparsedDashboard := model.Resource{
		ID:     "dashboard-unparsed",
		Type:   model.ResourceTypeDashboard,
		Name:   "Absolute Window",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:absolute"},
		Metadata: map[string]string{
			model.MetadataDashboardTimeRange: "not-a-duration",
		},
		Status: model.ResourceStatusActive,
	}
	sampleDashboard := model.Resource{
		ID:     "dashboard-sample",
		Type:   model.ResourceTypeDashboard,
		Name:   "Sample",
		Source: model.SourceInfo{System: "sample", Instance: "local", ExternalID: "dashboard:sample"},
		Metadata: map[string]string{
			model.MetadataDashboardTimeRange: "336h0m0s",
		},
		Status: model.ResourceStatusActive,
	}
	deprecatedDashboard := model.Resource{
		ID:     "dashboard-deprecated-long",
		Type:   model.ResourceTypeDashboard,
		Name:   "Deprecated Long Window",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:deprecated-long"},
		Metadata: map[string]string{
			model.MetadataDashboardTimeRange: "336h0m0s",
		},
		Status: model.ResourceStatusDeprecated,
	}
	for _, resource := range []model.Resource{normalDashboard, longDashboard, unparsedDashboard, sampleDashboard, deprecatedDashboard} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewLongDashboardTimeRangeAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != longDashboard.ID {
		t.Fatalf("expected long dashboard finding, got %s", findings[0].Resource.ID)
	}
	if findings[0].Metadata["time_range"] != "336h0m0s" {
		t.Fatalf("expected time range metadata, got %#v", findings[0].Metadata)
	}
}

func TestLongDashboardTimeRangeAnalyzerConfig(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	dashboard := model.Resource{
		ID:     "dashboard-long",
		Type:   model.ResourceTypeDashboard,
		Name:   "Long Window",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:long"},
		Metadata: map[string]string{
			model.MetadataDashboardUID:       "long",
			model.MetadataDashboardTimeRange: "336h0m0s",
		},
		Status: model.ResourceStatusActive,
	}
	if err := store.Resources.Upsert(ctx, dashboard); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewLongDashboardTimeRangeAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"long_dashboard_time_range_threshold": "400h",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no finding with higher threshold, got %d", len(findings))
	}

	findings, err = NewLongDashboardTimeRangeAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"allowed_long_dashboard_time_ranges": "long",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer with allowlist: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no finding for allowed dashboard, got %d", len(findings))
	}
}
