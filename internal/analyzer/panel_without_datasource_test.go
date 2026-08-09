package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPanelWithoutDatasourceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	panelWithDatasource := model.Resource{ID: "panel-with-ds", Type: model.ResourceTypePanel, Name: "Request Rate", Status: model.ResourceStatusActive}
	panelWithoutDatasource := model.Resource{ID: "panel-without-ds", Type: model.ResourceTypePanel, Name: "Legacy Panel", Status: model.ResourceStatusActive}
	panelWithResolutionMetadata := model.Resource{
		ID:       "panel-query-metadata",
		Type:     model.ResourceTypePanel,
		Name:     "Text Panel",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataPanelQueryCount: "0"},
	}
	panelWithDeprecatedDatasource := model.Resource{ID: "panel-with-deprecated-ds", Type: model.ResourceTypePanel, Name: "Old Datasource Panel", Status: model.ResourceStatusActive}
	deprecatedPanel := model.Resource{ID: "panel-deprecated", Type: model.ResourceTypePanel, Name: "Deprecated Panel", Status: model.ResourceStatusDeprecated}
	datasource := model.Resource{ID: "datasource-1", Type: model.ResourceTypeDatasource, Name: "Prometheus", Status: model.ResourceStatusActive}
	deprecatedDatasource := model.Resource{ID: "datasource-old", Type: model.ResourceTypeDatasource, Name: "Old Prometheus", Status: model.ResourceStatusDeprecated}
	for _, resource := range []model.Resource{panelWithDatasource, panelWithoutDatasource, panelWithResolutionMetadata, panelWithDeprecatedDatasource, deprecatedPanel, datasource, deprecatedDatasource} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	relationships := []model.Relationship{
		{ID: "panel-with-ds-uses-datasource", FromID: panelWithDatasource.ID, ToID: datasource.ID, Type: model.RelationshipUses, CreatedAt: now},
		{ID: "panel-with-deprecated-ds-uses-datasource", FromID: panelWithDeprecatedDatasource.ID, ToID: deprecatedDatasource.ID, Type: model.RelationshipUses, CreatedAt: now},
	}
	for _, relationship := range relationships {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewPanelWithoutDatasourceAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(findings), findings)
	}
	found := map[string]bool{}
	for _, finding := range findings {
		if finding.Type != "PanelWithoutDatasource" {
			t.Fatalf("expected PanelWithoutDatasource finding, got %#v", finding)
		}
		found[finding.Resource.ID] = true
	}
	if !found[panelWithoutDatasource.ID] || !found[panelWithDeprecatedDatasource.ID] {
		t.Fatalf("expected panel findings for missing and deprecated datasources, got %#v", findings)
	}
	if found[deprecatedPanel.ID] {
		t.Fatalf("did not expect deprecated panel finding, got %#v", findings)
	}
}

func TestPanelWithoutDatasourceAnalyzerWithoutGraph(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	if err := store.Resources.Upsert(ctx, model.Resource{ID: "panel-without-ds", Type: model.ResourceTypePanel, Name: "Legacy Panel", Status: model.ResourceStatusActive}); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewPanelWithoutDatasourceAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings without graph, got %#v", findings)
	}
}
