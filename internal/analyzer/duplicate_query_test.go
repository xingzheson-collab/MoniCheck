package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDuplicateQueryAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	primaryPanel := model.Resource{
		ID:     "panel-primary",
		Type:   model.ResourceTypePanel,
		Name:   "Request Rate",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total[5m]))",
		},
	}
	duplicateAlert := model.Resource{
		ID:     "alert-duplicate",
		Type:   model.ResourceTypeAlertRule,
		Name:   "APIHighRequestRate",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum( rate( http_requests_total[5m] ) )",
		},
	}
	uniquePanel := model.Resource{
		ID:     "panel-unique",
		Type:   model.ResourceTypePanel,
		Name:   "Errors",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_errors_total[5m]))",
		},
	}
	inactiveDuplicate := model.Resource{
		ID:     "panel-inactive",
		Type:   model.ResourceTypePanel,
		Name:   "Inactive",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total[5m]))",
		},
	}
	disabledDuplicateAlert := model.Resource{
		ID:     "alert-disabled",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DisabledDuplicateQueryAlert",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL:   "sum(rate(http_requests_total[5m]))",
			model.MetadataDisabled: "true",
		},
	}
	emptyDashboard := model.Resource{
		ID:     "dashboard-empty",
		Type:   model.ResourceTypeDashboard,
		Name:   "Empty",
		Status: model.ResourceStatusActive,
	}

	for _, resource := range []model.Resource{primaryPanel, duplicateAlert, uniquePanel, inactiveDuplicate, disabledDuplicateAlert, emptyDashboard} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewDuplicateQueryAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "DuplicateQuery" || findings[0].Resource.ID != primaryPanel.ID {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if findings[0].Metadata["duplicate_count"] != "2" {
		t.Fatalf("expected duplicate count metadata, got %#v", findings[0].Metadata)
	}
}
