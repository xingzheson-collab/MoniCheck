package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPanelWithoutUnitAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	withUnit := model.Resource{
		ID:     "panel-with-unit",
		Type:   model.ResourceTypePanel,
		Name:   "Latency",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:1"},
		Metadata: map[string]string{
			model.MetadataVisualizationType: "timeseries",
			model.MetadataPanelUnit:         "ms",
		},
		Status: model.ResourceStatusActive,
	}
	withoutUnit := model.Resource{
		ID:     "panel-without-unit",
		Type:   model.ResourceTypePanel,
		Name:   "Request Rate",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:2"},
		Metadata: map[string]string{
			model.MetadataVisualizationType: "timeseries",
			model.MetadataPanelUnit:         "short",
		},
		Status: model.ResourceStatusActive,
	}
	deprecatedWithoutUnit := model.Resource{
		ID:     "panel-deprecated-without-unit",
		Type:   model.ResourceTypePanel,
		Name:   "Deprecated Request Rate",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:deprecated"},
		Metadata: map[string]string{
			model.MetadataVisualizationType: "timeseries",
			model.MetadataPanelUnit:         "short",
		},
		Status: model.ResourceStatusDeprecated,
	}
	textPanel := model.Resource{
		ID:     "panel-text",
		Type:   model.ResourceTypePanel,
		Name:   "Notes",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:3"},
		Metadata: map[string]string{
			model.MetadataVisualizationType: "text",
		},
		Status: model.ResourceStatusActive,
	}
	samplePanel := model.Resource{
		ID:     "panel-sample",
		Type:   model.ResourceTypePanel,
		Name:   "Sample",
		Source: model.SourceInfo{System: "sample", Instance: "local", ExternalID: "panel:sample:1"},
		Metadata: map[string]string{
			model.MetadataVisualizationType: "timeseries",
		},
		Status: model.ResourceStatusActive,
	}
	for _, resource := range []model.Resource{withUnit, withoutUnit, deprecatedWithoutUnit, textPanel, samplePanel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	analyzer := NewPanelWithoutUnitAnalyzer()
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := analyzer.Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != withoutUnit.ID {
		t.Fatalf("expected panel without unit finding, got %s", findings[0].Resource.ID)
	}
	if findings[0].Type != "PanelWithoutUnit" {
		t.Fatalf("expected PanelWithoutUnit finding type, got %s", findings[0].Type)
	}
}

func TestPanelWithoutUnitAnalyzerAllowsConfiguredPanels(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	panel := model.Resource{
		ID:     "panel-without-unit",
		Type:   model.ResourceTypePanel,
		Name:   "Request Rate",
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

	findings, err := NewPanelWithoutUnitAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"allowed_panels_without_unit": "2",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no finding for allowed panel, got %d", len(findings))
	}
}
