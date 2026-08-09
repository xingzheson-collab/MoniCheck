package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestHighImpactDatasourceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	coreDatasource := model.Resource{
		ID:     "datasource-core",
		Type:   model.ResourceTypeDatasource,
		Name:   "Prometheus Core",
		Status: model.ResourceStatusActive,
	}
	lowImpactDatasource := model.Resource{
		ID:     "datasource-low",
		Type:   model.ResourceTypeDatasource,
		Name:   "Prometheus Sandbox",
		Status: model.ResourceStatusActive,
	}
	deprecatedDatasource := model.Resource{
		ID:     "datasource-deprecated",
		Type:   model.ResourceTypeDatasource,
		Name:   "Old Prometheus",
		Status: model.ResourceStatusDeprecated,
	}
	consumers := []model.Resource{
		{ID: "dashboard-api", Type: model.ResourceTypeDashboard, Name: "API Overview", Status: model.ResourceStatusActive},
		{ID: "panel-rate", Type: model.ResourceTypePanel, Name: "Request Rate", Status: model.ResourceStatusActive},
		{ID: "alert-error", Type: model.ResourceTypeAlertRule, Name: "APIHighErrorRate", Status: model.ResourceStatusActive},
		{ID: "recording-rate", Type: model.ResourceTypeRecordingRule, Name: "job:http_requests:rate5m", Status: model.ResourceStatusActive},
	}
	inactiveConsumer := model.Resource{
		ID:     "panel-inactive",
		Type:   model.ResourceTypePanel,
		Name:   "Inactive Panel",
		Status: model.ResourceStatusDeprecated,
	}
	metric := model.Resource{
		ID:     "metric-http",
		Type:   model.ResourceTypeMetric,
		Name:   "http_requests_total",
		Status: model.ResourceStatusActive,
	}

	resources := []model.Resource{coreDatasource, lowImpactDatasource, deprecatedDatasource, inactiveConsumer, metric}
	resources = append(resources, consumers...)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	relationships := []model.Relationship{
		{ID: "dashboard-uses-core", FromID: "dashboard-api", ToID: coreDatasource.ID, Type: model.RelationshipUses},
		{ID: "panel-uses-core", FromID: "panel-rate", ToID: coreDatasource.ID, Type: model.RelationshipUses},
		{ID: "alert-uses-core", FromID: "alert-error", ToID: coreDatasource.ID, Type: model.RelationshipUses},
		{ID: "recording-uses-core", FromID: "recording-rate", ToID: coreDatasource.ID, Type: model.RelationshipUses},
		{ID: "duplicate-panel-uses-core", FromID: "panel-rate", ToID: coreDatasource.ID, Type: model.RelationshipReferences},
		{ID: "inactive-panel-uses-core", FromID: inactiveConsumer.ID, ToID: coreDatasource.ID, Type: model.RelationshipUses},
		{ID: "metric-uses-core", FromID: metric.ID, ToID: coreDatasource.ID, Type: model.RelationshipUses},
		{ID: "dashboard-uses-low", FromID: "dashboard-api", ToID: lowImpactDatasource.ID, Type: model.RelationshipUses},
		{ID: "dashboard-uses-deprecated", FromID: "dashboard-api", ToID: deprecatedDatasource.ID, Type: model.RelationshipUses},
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

	findings, err := NewHighImpactDatasourceAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"high_impact_datasource_consumer_threshold": 2},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Type != "HighImpactDatasource" || finding.Resource.ID != coreDatasource.ID {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.Metadata["consumer_count"] != "4" {
		t.Fatalf("expected 4 consumers after filtering/dedup, got %#v", finding.Metadata)
	}
}
