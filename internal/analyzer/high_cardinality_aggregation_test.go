package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestHighCardinalityAggregationAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	lowCardinality := model.Resource{
		ID:     "panel-low",
		Type:   model.ResourceTypePanel,
		Name:   "Low Cardinality",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum by (job, service) (rate(http_requests_total[5m]))",
		},
	}
	highCardinality := model.Resource{
		ID:     "rule-high",
		Type:   model.ResourceTypeAlertRule,
		Name:   "HighCardinalityGrouping",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum by (cluster, namespace, pod, container, status) (rate(http_requests_total[5m])) > 10",
		},
	}
	withoutGrouping := model.Resource{
		ID:     "recording-without",
		Type:   model.ResourceTypeRecordingRule,
		Name:   "job:http_requests:rate5m",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum without (instance) (rate(http_requests_total[5m]))",
		},
	}
	dashboardVariableHighCardinality := model.Resource{
		ID:     "dashboard-high-cardinality-variable",
		Type:   model.ResourceTypeDashboard,
		Name:   "High Cardinality Variable",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum by (cluster, namespace, pod, container, status, code) (rate(http_requests_total[5m]))",
		},
	}
	for _, resource := range []model.Resource{lowCardinality, highCardinality, withoutGrouping, dashboardVariableHighCardinality} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewHighCardinalityAggregationAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	assertFindingForResourceType(t, findings, "HighCardinalityAggregation", highCardinality.ID)
	assertFindingForResourceType(t, findings, "HighCardinalityAggregation", dashboardVariableHighCardinality.ID)
	for _, finding := range findings {
		if finding.Resource.ID == highCardinality.ID && finding.Metadata["grouping_labels"] != "cluster,namespace,pod,container,status" {
			t.Fatalf("unexpected grouping labels: %#v", finding.Metadata)
		}
	}
}

func TestHighCardinalityAggregationAnalyzerCustomThreshold(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	panel := model.Resource{
		ID:     "panel-three-labels",
		Type:   model.ResourceTypePanel,
		Name:   "Three Labels",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum by (job, service, code) (rate(http_requests_total[5m]))",
		},
	}
	if err := store.Resources.Upsert(ctx, panel); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewHighCardinalityAggregationAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"aggregation_label_threshold": 2},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != panel.ID {
		t.Fatalf("expected finding for %s, got %#v", panel.ID, findings)
	}
}
