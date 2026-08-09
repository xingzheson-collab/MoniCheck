package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestHighImpactServiceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	coreService := model.Resource{
		ID:     "service-api",
		Type:   model.ResourceTypeService,
		Name:   "api",
		Status: model.ResourceStatusActive,
	}
	lowImpactService := model.Resource{
		ID:     "service-worker",
		Type:   model.ResourceTypeService,
		Name:   "worker",
		Status: model.ResourceStatusActive,
	}
	deprecatedService := model.Resource{
		ID:     "service-old",
		Type:   model.ResourceTypeService,
		Name:   "old",
		Status: model.ResourceStatusDeprecated,
	}
	members := []model.Resource{
		{ID: "metric-api", Type: model.ResourceTypeMetric, Name: "http_requests_total", Status: model.ResourceStatusActive},
		{ID: "dashboard-api", Type: model.ResourceTypeDashboard, Name: "API Overview", Status: model.ResourceStatusActive},
		{ID: "panel-api", Type: model.ResourceTypePanel, Name: "Request Rate", Status: model.ResourceStatusActive},
		{ID: "alert-api", Type: model.ResourceTypeAlertRule, Name: "APIHighErrorRate", Status: model.ResourceStatusActive},
	}
	inactiveMember := model.Resource{
		ID:     "panel-inactive",
		Type:   model.ResourceTypePanel,
		Name:   "Inactive Panel",
		Status: model.ResourceStatusDeprecated,
	}
	serviceChild := model.Resource{
		ID:     "service-child",
		Type:   model.ResourceTypeService,
		Name:   "child",
		Status: model.ResourceStatusActive,
	}

	resources := []model.Resource{coreService, lowImpactService, deprecatedService, inactiveMember, serviceChild}
	resources = append(resources, members...)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	relationships := []model.Relationship{
		{ID: "metric-belongs-core", FromID: "metric-api", ToID: coreService.ID, Type: model.RelationshipBelongsTo},
		{ID: "dashboard-belongs-core", FromID: "dashboard-api", ToID: coreService.ID, Type: model.RelationshipBelongsTo},
		{ID: "panel-belongs-core", FromID: "panel-api", ToID: coreService.ID, Type: model.RelationshipBelongsTo},
		{ID: "alert-belongs-core", FromID: "alert-api", ToID: coreService.ID, Type: model.RelationshipBelongsTo},
		{ID: "duplicate-panel-belongs-core", FromID: "panel-api", ToID: coreService.ID, Type: model.RelationshipBelongsTo},
		{ID: "inactive-panel-belongs-core", FromID: inactiveMember.ID, ToID: coreService.ID, Type: model.RelationshipBelongsTo},
		{ID: "service-child-belongs-core", FromID: serviceChild.ID, ToID: coreService.ID, Type: model.RelationshipBelongsTo},
		{ID: "metric-belongs-low", FromID: "metric-api", ToID: lowImpactService.ID, Type: model.RelationshipBelongsTo},
		{ID: "metric-belongs-deprecated", FromID: "metric-api", ToID: deprecatedService.ID, Type: model.RelationshipBelongsTo},
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

	findings, err := NewHighImpactServiceAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"high_impact_service_resource_threshold": 3},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Type != "HighImpactService" || finding.Resource.ID != coreService.ID {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.Metadata["resource_count"] != "4" {
		t.Fatalf("expected 4 active monitoring members after filtering/dedup, got %#v", finding.Metadata)
	}
}

func TestHighImpactServiceAnalyzerIncludesDerivedMetricImpact(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	service := model.Resource{ID: "service-api", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive}
	rawMetric := model.Resource{ID: "metric-raw", Type: model.ResourceTypeMetric, Name: "http_requests_total", Status: model.ResourceStatusActive}
	derivedMetric := model.Resource{ID: "metric-derived", Type: model.ResourceTypeMetric, Name: "job:http_requests:rate5m", Status: model.ResourceStatusActive}
	recordingRule := model.Resource{ID: "record-api", Type: model.ResourceTypeRecordingRule, Name: "job:http_requests:rate5m", Status: model.ResourceStatusActive}
	panel := model.Resource{ID: "panel-api", Type: model.ResourceTypePanel, Name: "API throughput", Status: model.ResourceStatusActive}
	resources := []model.Resource{service, rawMetric, derivedMetric, recordingRule, panel}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	relationships := []model.Relationship{
		{ID: "metric-belongs-service", FromID: rawMetric.ID, ToID: service.ID, Type: model.RelationshipBelongsTo},
		{ID: "record-uses-raw", FromID: recordingRule.ID, ToID: rawMetric.ID, Type: model.RelationshipUses},
		{ID: "record-produces-derived", FromID: recordingRule.ID, ToID: derivedMetric.ID, Type: model.RelationshipProduces},
		{ID: "raw-produces-derived", FromID: rawMetric.ID, ToID: derivedMetric.ID, Type: model.RelationshipProduces},
		{ID: "panel-uses-derived", FromID: panel.ID, ToID: derivedMetric.ID, Type: model.RelationshipUses},
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

	findings, err := NewHighImpactServiceAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"high_impact_service_resource_threshold": 3},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected derived metric impact to trigger one finding, got %#v", findings)
	}
	if findings[0].Resource.ID != service.ID || findings[0].Metadata["resource_count"] != "4" {
		t.Fatalf("expected service impact to include raw metric, recording rule, derived metric, and panel, got %#v", findings[0])
	}
}
