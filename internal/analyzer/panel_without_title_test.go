package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPanelWithoutTitleAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	withTitle := model.Resource{
		ID:       "panel-with-title",
		Type:     model.ResourceTypePanel,
		Name:     "CPU",
		Source:   model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:1"},
		Metadata: map[string]string{model.MetadataPanelTitle: "CPU"},
		Status:   model.ResourceStatusActive,
	}
	withoutTitle := model.Resource{
		ID:       "panel-without-title",
		Type:     model.ResourceTypePanel,
		Name:     "panel:api:2",
		Source:   model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:2"},
		Metadata: map[string]string{},
		Status:   model.ResourceStatusActive,
	}
	deprecatedWithoutTitle := model.Resource{
		ID:       "panel-deprecated-without-title",
		Type:     model.ResourceTypePanel,
		Name:     "deprecated",
		Source:   model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:api:deprecated"},
		Metadata: map[string]string{},
		Status:   model.ResourceStatusDeprecated,
	}
	samplePanel := model.Resource{
		ID:     "panel-sample",
		Type:   model.ResourceTypePanel,
		Name:   "Sample Panel",
		Source: model.SourceInfo{System: "sample", Instance: "local", ExternalID: "panel:sample:1"},
		Status: model.ResourceStatusActive,
	}
	for _, resource := range []model.Resource{withTitle, withoutTitle, deprecatedWithoutTitle, samplePanel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	analyzer := NewPanelWithoutTitleAnalyzer()
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
	if findings[0].Resource.ID != withoutTitle.ID {
		t.Fatalf("expected panel without title finding, got %s", findings[0].Resource.ID)
	}
	if findings[0].Type != "PanelWithoutTitle" {
		t.Fatalf("expected PanelWithoutTitle finding type, got %s", findings[0].Type)
	}
}
