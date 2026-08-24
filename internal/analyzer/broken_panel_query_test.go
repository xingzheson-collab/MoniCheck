package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBrokenPanelQueryAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	goodPanel := model.Resource{
		ID:     "panel-good",
		Type:   model.ResourceTypePanel,
		Name:   "Request Rate",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:good"},
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total[5m]))",
		},
	}
	emptyPanel := model.Resource{
		ID:     "panel-empty",
		Type:   model.ResourceTypePanel,
		Name:   "Empty",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:empty"},
	}
	badPanel := model.Resource{
		ID:     "panel-bad",
		Type:   model.ResourceTypePanel,
		Name:   "Bad",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:bad"},
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate([5m]))",
		},
	}
	deadPanel := model.Resource{
		ID:     "panel-dead-metric",
		Type:   model.ResourceTypePanel,
		Name:   "Dead metric",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:dead"},
		Metadata: map[string]string{
			model.MetadataPromQL: "rate(removed_metric_total[5m])",
		},
	}
	deprecatedEmptyPanel := model.Resource{
		ID:     "panel-deprecated-empty",
		Type:   model.ResourceTypePanel,
		Name:   "Deprecated Empty",
		Status: model.ResourceStatusDeprecated,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:deprecated"},
	}
	sampleEmptyPanel := model.Resource{
		ID:     "panel-sample-empty",
		Type:   model.ResourceTypePanel,
		Name:   "Sample Empty",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "sample", Instance: "local", ExternalID: "panel:sample"},
	}

	for _, resource := range []model.Resource{goodPanel, emptyPanel, badPanel, deadPanel, deprecatedEmptyPanel, sampleEmptyPanel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID: "dead-panel-uses-metric", FromID: deadPanel.ID, ToID: "missing-bound-metric", Type: model.RelationshipUses,
		Metadata: map[string]string{model.MetadataMetricInventoryBinding: "EXACT"},
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewBrokenPanelQueryAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	assertFindingType(t, findings, "MissingPanelQuery")
	assertFindingType(t, findings, "UnresolvedPanelQueryMetric")
	assertFindingType(t, findings, "PanelMetricNotCollected")
	for _, finding := range findings {
		if finding.Type == "PanelMetricNotCollected" && finding.Severity != model.SeverityCritical {
			t.Fatalf("expected dead bound panel metric to be critical, got %#v", finding)
		}
	}
}
