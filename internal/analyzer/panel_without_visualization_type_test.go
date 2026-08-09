package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPanelWithoutVisualizationTypeAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	withType := model.Resource{
		ID:       "panel-with-type",
		Type:     model.ResourceTypePanel,
		Name:     "Request Rate",
		Source:   model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:1"},
		Metadata: map[string]string{model.MetadataVisualizationType: "timeseries"},
		Status:   model.ResourceStatusActive,
	}
	withoutType := model.Resource{
		ID:       "panel-without-type",
		Type:     model.ResourceTypePanel,
		Name:     "Legacy Panel",
		Source:   model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:2"},
		Metadata: map[string]string{model.MetadataPanelID: "2"},
		Status:   model.ResourceStatusActive,
	}
	deprecatedWithoutType := model.Resource{
		ID:       "panel-deprecated-without-type",
		Type:     model.ResourceTypePanel,
		Name:     "Deprecated Panel",
		Source:   model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:deprecated"},
		Metadata: map[string]string{model.MetadataPanelID: "3"},
		Status:   model.ResourceStatusDeprecated,
	}
	nonGrafana := model.Resource{
		ID:     "panel-sample",
		Type:   model.ResourceTypePanel,
		Name:   "Sample Panel",
		Source: model.SourceInfo{System: "sample", Instance: "local", ExternalID: "panel:sample:1"},
		Status: model.ResourceStatusActive,
	}
	for _, resource := range []model.Resource{withType, withoutType, deprecatedWithoutType, nonGrafana} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewPanelWithoutVisualizationTypeAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "PanelWithoutVisualizationType" || findings[0].Resource.ID != withoutType.ID {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}
