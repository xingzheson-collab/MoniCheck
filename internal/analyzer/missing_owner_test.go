package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestMissingOwnerAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	ownedMetric := model.Resource{
		ID:     "metric-owned",
		Type:   model.ResourceTypeMetric,
		Name:   "http_requests_total",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataOwner: "platform",
		},
	}
	teamOwnedRule := model.Resource{
		ID:     "rule-team-owned",
		Type:   model.ResourceTypeAlertRule,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{
			"team": "platform",
		},
	}
	ownedService := model.Resource{
		ID:     "service-owned",
		Type:   model.ResourceTypeService,
		Name:   "api",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{
			"team": "platform",
		},
	}
	unownedDashboard := model.Resource{ID: "dashboard-unowned", Type: model.ResourceTypeDashboard, Name: "Legacy Dashboard", Status: model.ResourceStatusActive}
	unownedService := model.Resource{ID: "service-unowned", Type: model.ResourceTypeService, Name: "legacy", Status: model.ResourceStatusActive}
	deprecatedUnownedDashboard := model.Resource{ID: "dashboard-deprecated", Type: model.ResourceTypeDashboard, Name: "Deprecated Dashboard", Status: model.ResourceStatusDeprecated}
	disabledUnownedAlertRule := model.Resource{
		ID:     "rule-disabled",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DisabledAlert",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDisabled: "true",
		},
	}

	for _, resource := range []model.Resource{ownedMetric, teamOwnedRule, ownedService, unownedDashboard, unownedService, deprecatedUnownedDashboard, disabledUnownedAlertRule} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewMissingOwnerAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
		assertEnglishRecommendation(t, finding)
	}
	if !found[unownedDashboard.ID] || !found[unownedService.ID] {
		t.Fatalf("expected missing owner findings for dashboard and service, got %#v", findings)
	}
}

func TestMissingOwnerAnalyzerConfiguredOwnerKeys(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	rule := model.Resource{
		ID:     "rule-team-owned",
		Type:   model.ResourceTypeAlertRule,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{
			"team": "platform",
		},
	}
	if err := store.Resources.Upsert(ctx, rule); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewMissingOwnerAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config: map[string]any{
			"owner_keys": []string{model.MetadataOwner},
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected strict owner config to produce 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != rule.ID {
		t.Fatalf("expected missing owner finding for %s, got %s", rule.ID, findings[0].Resource.ID)
	}
}
