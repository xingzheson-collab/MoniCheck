package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestUnattributedMonitoringResourceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	service := model.Resource{ID: "service-api", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive}
	attributedAlert := model.Resource{ID: "alert-api", Type: model.ResourceTypeAlertRule, Name: "APIHighErrorRate", Status: model.ResourceStatusActive}
	labeledDashboard := model.Resource{
		ID:     "dashboard-api",
		Type:   model.ResourceTypeDashboard,
		Name:   "API Overview",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{"service": "api"},
	}
	unattributedRecording := model.Resource{ID: "recording-missing", Type: model.ResourceTypeRecordingRule, Name: "job:http_requests:rate5m", Status: model.ResourceStatusActive}
	disabledAlert := model.Resource{
		ID:       "alert-disabled",
		Type:     model.ResourceTypeAlertRule,
		Name:     "DisabledAlert",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataDisabled: "true"},
	}
	inactiveDashboard := model.Resource{ID: "dashboard-old", Type: model.ResourceTypeDashboard, Name: "Old Dashboard", Status: model.ResourceStatusDeprecated}
	datasource := model.Resource{ID: "datasource-prom", Type: model.ResourceTypeDatasource, Name: "Prometheus", Status: model.ResourceStatusActive}

	for _, resource := range []model.Resource{service, attributedAlert, labeledDashboard, unattributedRecording, disabledAlert, inactiveDashboard, datasource} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{ID: "alert-service", FromID: attributedAlert.ID, ToID: service.ID, Type: model.RelationshipBelongsTo}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewUnattributedMonitoringResourceAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Type != "UnattributedMonitoringResource" || findings[0].Resource.ID != unattributedRecording.ID {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}
