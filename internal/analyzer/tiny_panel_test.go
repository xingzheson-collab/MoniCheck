package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestTinyPanelAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	normalPanel := model.Resource{
		ID:     "panel-normal",
		Type:   model.ResourceTypePanel,
		Name:   "Normal Panel",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:normal"},
		Metadata: map[string]string{
			model.MetadataPanelGridW: "12",
			model.MetadataPanelGridH: "8",
		},
	}
	tinyPanel := model.Resource{
		ID:     "panel-tiny",
		Type:   model.ResourceTypePanel,
		Name:   "Tiny Panel",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:tiny"},
		Metadata: map[string]string{
			model.MetadataPanelGridW: "2",
			model.MetadataPanelGridH: "3",
		},
	}
	missingGridPanel := model.Resource{
		ID:       "panel-missing-grid",
		Type:     model.ResourceTypePanel,
		Name:     "Missing Grid Panel",
		Status:   model.ResourceStatusActive,
		Source:   model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:missing-grid"},
		Metadata: map[string]string{},
	}
	deprecatedTinyPanel := model.Resource{
		ID:     "panel-deprecated-tiny",
		Type:   model.ResourceTypePanel,
		Name:   "Deprecated Tiny Panel",
		Status: model.ResourceStatusDeprecated,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:deprecated-tiny"},
		Metadata: map[string]string{
			model.MetadataPanelGridW: "2",
			model.MetadataPanelGridH: "3",
		},
	}
	samplePanel := model.Resource{
		ID:     "panel-sample",
		Type:   model.ResourceTypePanel,
		Name:   "Sample Panel",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "sample", Instance: "local", ExternalID: "panel:sample"},
		Metadata: map[string]string{
			model.MetadataPanelGridW: "2",
			model.MetadataPanelGridH: "3",
		},
	}
	for _, resource := range []model.Resource{normalPanel, tinyPanel, missingGridPanel, deprecatedTinyPanel, samplePanel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewTinyPanelAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "TinyPanel" {
		t.Fatalf("expected TinyPanel, got %s", findings[0].Type)
	}
	if findings[0].Resource.ID != tinyPanel.ID {
		t.Fatalf("expected tiny panel finding, got %s", findings[0].Resource.ID)
	}
}

func TestTinyPanelAnalyzerConfiguredThreshold(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	panel := model.Resource{
		ID:     "panel",
		Type:   model.ResourceTypePanel,
		Name:   "Panel",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel"},
		Metadata: map[string]string{
			model.MetadataPanelGridW: "2",
			model.MetadataPanelGridH: "3",
		},
	}
	if err := store.Resources.Upsert(ctx, panel); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewTinyPanelAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config: map[string]any{
			"tiny_panel_area_threshold": 4,
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
