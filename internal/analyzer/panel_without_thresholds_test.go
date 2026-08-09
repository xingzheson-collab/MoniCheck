package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPanelWithoutThresholdsAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	withThresholds := model.Resource{
		ID:     "panel-with-thresholds",
		Type:   model.ResourceTypePanel,
		Name:   "Error Budget",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:1"},
		Metadata: map[string]string{
			model.MetadataVisualizationType:   "gauge",
			model.MetadataPanelThresholdCount: "2",
		},
		Status: model.ResourceStatusActive,
	}
	withoutThresholds := model.Resource{
		ID:     "panel-without-thresholds",
		Type:   model.ResourceTypePanel,
		Name:   "SLO",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:2"},
		Metadata: map[string]string{
			model.MetadataDashboardUID:        "api",
			model.MetadataPanelID:             "2",
			model.MetadataVisualizationType:   "stat",
			model.MetadataPanelThresholdCount: "0",
		},
		Status: model.ResourceStatusActive,
	}
	deprecatedWithoutThresholds := model.Resource{
		ID:     "panel-deprecated-without-thresholds",
		Type:   model.ResourceTypePanel,
		Name:   "Deprecated SLO",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:deprecated"},
		Metadata: map[string]string{
			model.MetadataDashboardUID:        "api",
			model.MetadataPanelID:             "3",
			model.MetadataVisualizationType:   "stat",
			model.MetadataPanelThresholdCount: "0",
		},
		Status: model.ResourceStatusDeprecated,
	}
	timeSeriesPanel := model.Resource{
		ID:     "panel-timeseries",
		Type:   model.ResourceTypePanel,
		Name:   "Latency",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:3"},
		Metadata: map[string]string{
			model.MetadataVisualizationType: "timeseries",
		},
		Status: model.ResourceStatusActive,
	}
	samplePanel := model.Resource{
		ID:     "panel-sample",
		Type:   model.ResourceTypePanel,
		Name:   "Sample",
		Source: model.SourceInfo{System: "sample", Instance: "local", ExternalID: "panel:sample:1"},
		Metadata: map[string]string{
			model.MetadataVisualizationType: "stat",
		},
		Status: model.ResourceStatusActive,
	}
	for _, resource := range []model.Resource{withThresholds, withoutThresholds, deprecatedWithoutThresholds, timeSeriesPanel, samplePanel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewPanelWithoutThresholdsAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != withoutThresholds.ID {
		t.Fatalf("expected panel without thresholds finding, got %s", findings[0].Resource.ID)
	}
	if findings[0].Type != "PanelWithoutThresholds" {
		t.Fatalf("expected PanelWithoutThresholds finding type, got %s", findings[0].Type)
	}
}

func TestPanelWithoutThresholdsAnalyzerConfig(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	panel := model.Resource{
		ID:     "panel-without-thresholds",
		Type:   model.ResourceTypePanel,
		Name:   "Latency",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:2"},
		Metadata: map[string]string{
			model.MetadataDashboardUID:      "api",
			model.MetadataPanelID:           "2",
			model.MetadataVisualizationType: "timeseries",
		},
		Status: model.ResourceStatusActive,
	}
	if err := store.Resources.Upsert(ctx, panel); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewPanelWithoutThresholdsAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"panel_threshold_required_types": "timeseries",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected configured threshold finding, got %d", len(findings))
	}

	findings, err = NewPanelWithoutThresholdsAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"panel_threshold_required_types":    "timeseries",
			"allowed_panels_without_thresholds": "2",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer with allowlist: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no finding for allowed panel, got %d", len(findings))
	}
}
