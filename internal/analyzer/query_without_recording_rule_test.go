package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestQueryWithoutRecordingRuleAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	rawMetric := model.Resource{ID: "metric-raw", Type: model.ResourceTypeMetric, Name: "http_requests_total", Status: model.ResourceStatusActive}
	recordedMetric := model.Resource{ID: "metric-recorded", Type: model.ResourceTypeMetric, Name: "job:http_requests:rate7d", Status: model.ResourceStatusActive}
	recordingRule := model.Resource{
		ID:     "recording-rate7d",
		Type:   model.ResourceTypeRecordingRule,
		Name:   "job:http_requests:rate7d",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total[7d])) by (job)",
		},
	}
	recordedMetricForRollup := model.Resource{ID: "metric-recorded-rollup", Type: model.ResourceTypeMetric, Name: "job:http_requests:rate30d", Status: model.ResourceStatusActive}
	rollupRecordingRule := model.Resource{
		ID:     "recording-rate30d",
		Type:   model.ResourceTypeRecordingRule,
		Name:   "job:http_requests:rate30d",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum_over_time(job:http_requests:rate7d[30d])",
		},
	}
	longRangePanel := model.Resource{
		ID:     "panel-long-range",
		Type:   model.ResourceTypePanel,
		Name:   "Long Range Panel",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total[7d])) by (job)",
		},
	}
	panelUsingRecording := model.Resource{
		ID:     "panel-recorded",
		Type:   model.ResourceTypePanel,
		Name:   "Recorded Panel",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "job:http_requests:rate7d",
		},
	}
	shortRangePanel := model.Resource{
		ID:     "panel-short",
		Type:   model.ResourceTypePanel,
		Name:   "Short Range Panel",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total[5m])) by (job)",
		},
	}

	for _, resource := range []model.Resource{rawMetric, recordedMetric, recordingRule, recordedMetricForRollup, rollupRecordingRule, longRangePanel, panelUsingRecording, shortRangePanel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	relationships := []model.Relationship{
		{ID: "recording-produces", FromID: recordingRule.ID, ToID: recordedMetric.ID, Type: model.RelationshipProduces},
		{ID: "recording-uses-raw", FromID: recordingRule.ID, ToID: rawMetric.ID, Type: model.RelationshipUses},
		{ID: "rollup-recording-produces", FromID: rollupRecordingRule.ID, ToID: recordedMetricForRollup.ID, Type: model.RelationshipProduces},
		{ID: "rollup-recording-uses-recorded", FromID: rollupRecordingRule.ID, ToID: recordedMetric.ID, Type: model.RelationshipUses},
		{ID: "long-panel-uses-raw", FromID: longRangePanel.ID, ToID: rawMetric.ID, Type: model.RelationshipUses},
		{ID: "recorded-panel-uses-recorded", FromID: panelUsingRecording.ID, ToID: recordedMetric.ID, Type: model.RelationshipUses},
		{ID: "short-panel-uses-raw", FromID: shortRangePanel.ID, ToID: rawMetric.ID, Type: model.RelationshipUses},
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

	findings, err := NewQueryWithoutRecordingRuleAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
	}
	if !found[longRangePanel.ID] || !found[recordingRule.ID] {
		t.Fatalf("expected findings for long panel and first-level recording rule, got %#v", found)
	}
	if found[rollupRecordingRule.ID] {
		t.Fatalf("did not expect finding for rollup recording rule using recorded metric, got %#v", findings)
	}
}

func TestQueryWithoutRecordingRuleAnalyzerCustomLengthThreshold(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	alertRule := model.Resource{
		ID:     "alert-long-query",
		Type:   model.ResourceTypeAlertRule,
		Name:   "LongQueryAlert",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: `sum(rate(http_requests_total{job="api",handler!="/healthz"}[5m])) by (cluster, namespace, pod, handler) > 10`,
		},
	}
	if err := store.Resources.Upsert(ctx, alertRule); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewQueryWithoutRecordingRuleAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config: map[string]any{
			"query_without_recording_rule_length_threshold": 20,
			"query_without_recording_rule_range_threshold":  24 * time.Hour,
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != alertRule.ID {
		t.Fatalf("expected finding for %s, got %#v", alertRule.ID, findings)
	}
}
