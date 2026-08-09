package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestRequiredLabelsAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	labeledMetric := model.Resource{
		ID:     "metric-labeled",
		Type:   model.ResourceTypeMetric,
		Name:   "http_requests_total",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{
			"team":    "platform",
			"service": "api",
		},
	}
	unlabeledDashboard := model.Resource{
		ID:     "dashboard-unlabeled",
		Type:   model.ResourceTypeDashboard,
		Name:   "Legacy Dashboard",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{
			"team": "platform",
		},
	}
	deprecatedUnlabeledDashboard := model.Resource{
		ID:     "dashboard-deprecated",
		Type:   model.ResourceTypeDashboard,
		Name:   "Deprecated Dashboard",
		Status: model.ResourceStatusDeprecated,
	}
	disabledUnlabeledAlertRule := model.Resource{
		ID:     "alert-disabled",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DisabledAlert",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDisabled: "true",
		},
	}
	resolvedUnlabeledAlert := model.Resource{
		ID:     "alert-resolved",
		Type:   model.ResourceTypeAlert,
		Name:   "ResolvedAlert",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataAlertState: "resolved",
		},
	}
	unsupportedUnlabeledService := model.Resource{
		ID:     "service-api",
		Type:   model.ResourceTypeService,
		Name:   "api",
		Status: model.ResourceStatusActive,
	}

	for _, resource := range []model.Resource{labeledMetric, unlabeledDashboard, deprecatedUnlabeledDashboard, disabledUnlabeledAlertRule, resolvedUnlabeledAlert, unsupportedUnlabeledService} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewRequiredLabelsAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"required_resource_labels": "team,service"},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != unlabeledDashboard.ID {
		t.Fatalf("expected required labels finding for %s, got %s", unlabeledDashboard.ID, findings[0].Resource.ID)
	}
}
