package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestServiceOwnerMismatchAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	service := model.Resource{
		ID:     "service-api",
		Type:   model.ResourceTypeService,
		Name:   "api",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{
			model.MetadataOwner: "platform",
			"team":              "sre",
		},
	}
	inactiveService := model.Resource{
		ID:     "service-old",
		Type:   model.ResourceTypeService,
		Name:   "old-api",
		Status: model.ResourceStatusDeprecated,
		Labels: map[string]string{
			model.MetadataOwner: "legacy",
		},
	}
	mismatchedAlert := model.Resource{
		ID:     "alert-api",
		Type:   model.ResourceTypeAlertRule,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{
			model.MetadataOwner: "payments",
			"team":              "sre",
		},
	}
	matchedDashboard := model.Resource{
		ID:     "dashboard-api",
		Type:   model.ResourceTypeDashboard,
		Name:   "API Overview",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{
			model.MetadataOwner: "platform",
			"team":              "sre",
		},
	}
	missingOwnerMetric := model.Resource{ID: "metric-api", Type: model.ResourceTypeMetric, Name: "http_requests_total", Status: model.ResourceStatusActive}
	disabledAlert := model.Resource{
		ID:       "alert-disabled",
		Type:     model.ResourceTypeAlertRule,
		Name:     "DisabledAlert",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataDisabled: "true", model.MetadataOwner: "payments"},
	}
	oldTarget := model.Resource{
		ID:     "target-old-service",
		Type:   model.ResourceTypeTarget,
		Name:   "old-target",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{
			model.MetadataOwner: "new-team",
		},
	}

	for _, resource := range []model.Resource{service, inactiveService, mismatchedAlert, matchedDashboard, missingOwnerMetric, disabledAlert, oldTarget} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	relationships := []model.Relationship{
		{ID: "alert-service", FromID: mismatchedAlert.ID, ToID: service.ID, Type: model.RelationshipBelongsTo},
		{ID: "dashboard-service", FromID: matchedDashboard.ID, ToID: service.ID, Type: model.RelationshipBelongsTo},
		{ID: "metric-service", FromID: missingOwnerMetric.ID, ToID: service.ID, Type: model.RelationshipBelongsTo},
		{ID: "disabled-alert-service", FromID: disabledAlert.ID, ToID: service.ID, Type: model.RelationshipBelongsTo},
		{ID: "old-target-service", FromID: oldTarget.ID, ToID: inactiveService.ID, Type: model.RelationshipBelongsTo},
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

	findings, err := NewServiceOwnerMismatchAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(findings), findings)
	}
	finding := findings[0]
	if finding.Type != "ServiceOwnerMismatch" || finding.Resource.ID != mismatchedAlert.ID {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if !strings.Contains(finding.Metadata["mismatches"], `owner resource="payments" service="platform"`) {
		t.Fatalf("expected owner mismatch metadata, got %#v", finding.Metadata)
	}
	if strings.Contains(finding.Metadata["mismatches"], "team") {
		t.Fatalf("did not expect matching team to be reported, got %#v", finding.Metadata)
	}
}
