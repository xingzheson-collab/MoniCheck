package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPanelDatasourceResolutionAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		grafanaPanelWithDatasourceCounts("resolved", "0", "0", "0", model.ResourceStatusActive),
		grafanaPanelWithDatasourceCounts("unresolved", "2", "0", "0", model.ResourceStatusActive),
		grafanaPanelWithDatasourceCounts("missing", "0", "1", "0", model.ResourceStatusActive),
		grafanaPanelWithDatasourceCounts("both", "1", "3", "0", model.ResourceStatusActive),
		grafanaPanelWithDatasourceCounts("parse-error", "0", "0", "2", model.ResourceStatusActive),
		grafanaPanelWithDatasourceCounts("deprecated", "1", "1", "1", model.ResourceStatusDeprecated),
		{
			ID:       "other-source",
			Type:     model.ResourceTypePanel,
			Name:     "Other Source",
			Status:   model.ResourceStatusActive,
			Source:   model.SourceInfo{System: "sample"},
			Metadata: map[string]string{model.MetadataPanelUnresolvedDatasourceCount: "1", model.MetadataPanelQueryWithoutDatasource: "1"},
		},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	unresolved, err := NewUnresolvedPanelDatasourceAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute unresolved analyzer: %v", err)
	}
	assertPanelFindingIDs(t, unresolved, "unresolved", "both")
	for _, finding := range unresolved {
		if finding.Metadata["count"] == "" {
			t.Fatalf("expected aggregate count in unresolved finding: %#v", finding)
		}
	}

	missing, err := NewPanelQueryWithoutDatasourceAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute missing datasource analyzer: %v", err)
	}
	assertPanelFindingIDs(t, missing, "missing", "both")

	parseErrors, err := NewPanelQueryDependencyParseErrorAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute dependency parse error analyzer: %v", err)
	}
	assertPanelFindingIDs(t, parseErrors, "parse-error")
}

func grafanaPanelWithDatasourceCounts(id string, unresolved string, missing string, parseErrors string, status model.ResourceStatus) model.Resource {
	return model.Resource{
		ID:     id,
		Type:   model.ResourceTypePanel,
		Name:   id,
		Status: status,
		Source: model.SourceInfo{System: "grafana"},
		Metadata: map[string]string{
			model.MetadataPanelUnresolvedDatasourceCount: unresolved,
			model.MetadataPanelQueryWithoutDatasource:    missing,
			model.MetadataPanelDependencyParseErrorCount: parseErrors,
		},
	}
}

func assertPanelFindingIDs(t *testing.T, findings []model.Finding, expected ...string) {
	t.Helper()
	if len(findings) != len(expected) {
		t.Fatalf("expected %d findings, got %d: %#v", len(expected), len(findings), findings)
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
	}
	for _, id := range expected {
		if !found[id] {
			t.Fatalf("expected finding for %s, got %#v", id, findings)
		}
	}
}
