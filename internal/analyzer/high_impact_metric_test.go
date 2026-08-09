package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestHighImpactMetricAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	coreMetric := model.Resource{
		ID:     "metric-core",
		Type:   model.ResourceTypeMetric,
		Name:   "http_requests_total",
		Status: model.ResourceStatusActive,
	}
	lowImpactMetric := model.Resource{
		ID:     "metric-low",
		Type:   model.ResourceTypeMetric,
		Name:   "worker_queue_depth",
		Status: model.ResourceStatusActive,
	}
	deprecatedMetric := model.Resource{
		ID:     "metric-deprecated",
		Type:   model.ResourceTypeMetric,
		Name:   "old_metric_total",
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
	targetProducer := model.Resource{
		ID:     "target-producer",
		Type:   model.ResourceTypeTarget,
		Name:   "http://10.0.0.1:9100/metrics",
		Status: model.ResourceStatusActive,
	}

	resources := []model.Resource{coreMetric, lowImpactMetric, deprecatedMetric, inactiveConsumer, targetProducer}
	resources = append(resources, consumers...)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	relationships := []model.Relationship{
		{ID: "dashboard-uses-core", FromID: "dashboard-api", ToID: coreMetric.ID, Type: model.RelationshipUses},
		{ID: "panel-uses-core", FromID: "panel-rate", ToID: coreMetric.ID, Type: model.RelationshipUses},
		{ID: "alert-uses-core", FromID: "alert-error", ToID: coreMetric.ID, Type: model.RelationshipUses},
		{ID: "recording-uses-core", FromID: "recording-rate", ToID: coreMetric.ID, Type: model.RelationshipUses},
		{ID: "duplicate-panel-uses-core", FromID: "panel-rate", ToID: coreMetric.ID, Type: model.RelationshipReferences},
		{ID: "inactive-panel-uses-core", FromID: inactiveConsumer.ID, ToID: coreMetric.ID, Type: model.RelationshipUses},
		{ID: "target-produces-core", FromID: targetProducer.ID, ToID: coreMetric.ID, Type: model.RelationshipProduces},
		{ID: "dashboard-uses-low", FromID: "dashboard-api", ToID: lowImpactMetric.ID, Type: model.RelationshipUses},
		{ID: "dashboard-uses-deprecated", FromID: "dashboard-api", ToID: deprecatedMetric.ID, Type: model.RelationshipUses},
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

	findings, err := NewHighImpactMetricAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"high_impact_metric_consumer_threshold": 3},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Type != "HighImpactMetric" || finding.Resource.ID != coreMetric.ID {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.Metadata["consumer_count"] != "4" {
		t.Fatalf("expected 4 consumers after filtering/dedup, got %#v", finding.Metadata)
	}
}

func TestHighImpactMetricAnalyzerIncludesDerivedMetricConsumers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	rawMetric := model.Resource{ID: "metric-raw", Type: model.ResourceTypeMetric, Name: "http_requests_total", Status: model.ResourceStatusActive}
	recordedMetric := model.Resource{ID: "metric-recorded", Type: model.ResourceTypeMetric, Name: "job:http_requests:rate5m", Status: model.ResourceStatusActive}
	recordingRule := model.Resource{ID: "recording-rate", Type: model.ResourceTypeRecordingRule, Name: "job:http_requests:rate5m", Status: model.ResourceStatusActive}
	panel := model.Resource{ID: "panel-rate", Type: model.ResourceTypePanel, Name: "Request Rate", Status: model.ResourceStatusActive}
	alertRule := model.Resource{ID: "alert-errors", Type: model.ResourceTypeAlertRule, Name: "APIHighErrorRate", Status: model.ResourceStatusActive}
	dashboard := model.Resource{ID: "dashboard-api", Type: model.ResourceTypeDashboard, Name: "API Overview", Status: model.ResourceStatusActive}
	for _, resource := range []model.Resource{rawMetric, recordedMetric, recordingRule, panel, alertRule, dashboard} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	relationships := []model.Relationship{
		{ID: "recording-uses-raw", FromID: recordingRule.ID, ToID: rawMetric.ID, Type: model.RelationshipUses},
		{ID: "raw-produces-recorded", FromID: rawMetric.ID, ToID: recordedMetric.ID, Type: model.RelationshipProduces},
		{ID: "recording-produces-recorded", FromID: recordingRule.ID, ToID: recordedMetric.ID, Type: model.RelationshipProduces},
		{ID: "panel-uses-recorded", FromID: panel.ID, ToID: recordedMetric.ID, Type: model.RelationshipUses},
		{ID: "alert-uses-recorded", FromID: alertRule.ID, ToID: recordedMetric.ID, Type: model.RelationshipUses},
		{ID: "dashboard-uses-recorded", FromID: dashboard.ID, ToID: recordedMetric.ID, Type: model.RelationshipUses},
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

	findings, err := NewHighImpactMetricAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"high_impact_metric_consumer_threshold": 3},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Resource.ID != rawMetric.ID || findings[0].Metadata["consumer_count"] != "4" {
		t.Fatalf("expected raw metric with 4 direct/derived consumers, got %#v", findings[0])
	}
}
