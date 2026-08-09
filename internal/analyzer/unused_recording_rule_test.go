package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestUnusedRecordingRuleAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	usedRule := model.Resource{ID: "recording-used", Type: model.ResourceTypeRecordingRule, Name: "job:http_requests:rate5m", Status: model.ResourceStatusActive}
	usedByOutputRule := model.Resource{ID: "recording-output-used", Type: model.ResourceTypeRecordingRule, Name: "job:latency:p95", Status: model.ResourceStatusActive}
	unusedRule := model.Resource{ID: "recording-unused", Type: model.ResourceTypeRecordingRule, Name: "job:legacy:rate5m", Status: model.ResourceStatusActive}
	alertRule := model.Resource{ID: "alert-1", Type: model.ResourceTypeAlertRule, Name: "APIHighErrorRate", Status: model.ResourceStatusActive}
	panel := model.Resource{ID: "panel-latency", Type: model.ResourceTypePanel, Name: "Latency", Status: model.ResourceStatusActive}
	recordedMetric := model.Resource{ID: "metric-latency-p95", Type: model.ResourceTypeMetric, Name: "job:latency:p95", Status: model.ResourceStatusActive}

	for _, resource := range []model.Resource{usedRule, usedByOutputRule, unusedRule, alertRule, panel, recordedMetric} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	relationships := []model.Relationship{
		{ID: "alert-recording", FromID: alertRule.ID, ToID: usedRule.ID, Type: model.RelationshipUses},
		{ID: "recording-produces-metric", FromID: usedByOutputRule.ID, ToID: recordedMetric.ID, Type: model.RelationshipProduces},
		{ID: "panel-uses-recorded-metric", FromID: panel.ID, ToID: recordedMetric.ID, Type: model.RelationshipUses},
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

	findings, err := NewUnusedRecordingRuleAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != unusedRule.ID {
		t.Fatalf("expected unused recording rule finding for %s, got %s", unusedRule.ID, findings[0].Resource.ID)
	}
}
