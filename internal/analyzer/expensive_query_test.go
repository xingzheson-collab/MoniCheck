package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestExpensiveQueryAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	smallPanel := model.Resource{
		ID:     "panel-small",
		Type:   model.ResourceTypePanel,
		Name:   "Small Query",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total[5m]))",
		},
	}
	largePanel := model.Resource{
		ID:     "panel-large",
		Type:   model.ResourceTypePanel,
		Name:   "Large Query",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total{" + strings.Repeat(`label!="value",`, 40) + "}[5m]))",
		},
	}
	largeDashboardVariable := model.Resource{
		ID:     "dashboard-large-variable",
		Type:   model.ResourceTypeDashboard,
		Name:   "Large Variable Query",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "label_values(http_requests_total{" + strings.Repeat(`namespace!="ns",`, 40) + "}, pod)",
		},
	}
	deprecatedLargePanel := model.Resource{
		ID:     "panel-deprecated-large",
		Type:   model.ResourceTypePanel,
		Name:   "Deprecated Large Query",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(old_metric_total{" + strings.Repeat(`label!="value",`, 40) + "}[5m]))",
		},
	}
	disabledLargeAlert := model.Resource{
		ID:     "alert-disabled-large",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DisabledLargeQuery",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL:   "sum(rate(disabled_metric_total{" + strings.Repeat(`label!="value",`, 40) + "}[5m]))",
			model.MetadataDisabled: "true",
		},
	}

	for _, resource := range []model.Resource{smallPanel, largePanel, largeDashboardVariable, deprecatedLargePanel, disabledLargeAlert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewExpensiveQueryAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	assertFindingForResourceType(t, findings, "ExpensiveQuery", largePanel.ID)
	assertFindingForResourceType(t, findings, "ExpensiveQuery", largeDashboardVariable.ID)
}
