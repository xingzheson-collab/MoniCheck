package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestUnscopedQueryAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	scopedPanel := model.Resource{
		ID:     "panel-scoped",
		Type:   model.ResourceTypePanel,
		Name:   "Scoped Panel",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: `sum(rate(http_requests_total{job="api"}[5m]))`,
		},
	}
	unscopedPanel := model.Resource{
		ID:     "panel-unscoped",
		Type:   model.ResourceTypePanel,
		Name:   "Unscoped Panel",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total[5m]))",
		},
	}
	nameOnlyRule := model.Resource{
		ID:     "rule-name-only",
		Type:   model.ResourceTypeAlertRule,
		Name:   "NameOnlyMatcher",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: `{__name__="node_cpu_seconds_total"}`,
		},
	}
	dashboardVariable := model.Resource{
		ID:     "dashboard-variable",
		Type:   model.ResourceTypeDashboard,
		Name:   "Variable Dashboard",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "label_values(node_memory_MemAvailable_bytes, instance)",
		},
	}

	for _, resource := range []model.Resource{scopedPanel, unscopedPanel, nameOnlyRule, dashboardVariable} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewUnscopedQueryAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	assertFindingForResourceType(t, findings, "UnscopedQuery", unscopedPanel.ID)
	assertFindingForResourceType(t, findings, "UnscopedQuery", nameOnlyRule.ID)
	assertFindingForResourceType(t, findings, "UnscopedQuery", dashboardVariable.ID)
	for _, finding := range findings {
		if finding.Metadata["unscoped_metrics"] == "" || finding.Metadata["unscoped_count"] == "" {
			t.Fatalf("expected unscoped query metadata, got %#v", finding.Metadata)
		}
	}
}

func TestUnscopedQueryMetricsSkipsScopedSelectors(t *testing.T) {
	names := unscopedQueryMetrics(`sum(rate(a_total{service="api"}[5m])) + rate(b_total[5m])`)
	if len(names) != 1 || names[0] != "b_total" {
		t.Fatalf("expected only b_total to be unscoped, got %#v", names)
	}
}
