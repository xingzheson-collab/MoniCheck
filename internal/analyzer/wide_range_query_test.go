package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestWideRangeQueryAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	shortRange := model.Resource{
		ID:     "panel-short",
		Type:   model.ResourceTypePanel,
		Name:   "Short Range",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total[5m]))",
		},
	}
	longRange := model.Resource{
		ID:     "recording-long",
		Type:   model.ResourceTypeRecordingRule,
		Name:   "job:http_requests:rate7d",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total[7d])) by (job)",
		},
	}
	subqueryRange := model.Resource{
		ID:     "alert-subquery",
		Type:   model.ResourceTypeAlertRule,
		Name:   "WeeklyHighErrorRate",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "max_over_time(rate(http_requests_total[5m])[2d:5m]) > 1",
		},
	}
	dashboardVariableRange := model.Resource{
		ID:     "dashboard-variable-long",
		Type:   model.ResourceTypeDashboard,
		Name:   "Weekly Variable Query",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "label_values(max_over_time(http_requests_total[3d]), job)",
		},
	}
	for _, resource := range []model.Resource{shortRange, longRange, subqueryRange, dashboardVariableRange} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewWideRangeQueryAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	assertFindingForResourceType(t, findings, "WideRangeQuery", longRange.ID)
	assertFindingForResourceType(t, findings, "WideRangeQuery", subqueryRange.ID)
	assertFindingForResourceType(t, findings, "WideRangeQuery", dashboardVariableRange.ID)
}

func TestWideRangeQueryAnalyzerCustomThreshold(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	panel := model.Resource{
		ID:     "panel-6h",
		Type:   model.ResourceTypePanel,
		Name:   "Six Hour Range",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total[6h]))",
		},
	}
	if err := store.Resources.Upsert(ctx, panel); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewWideRangeQueryAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"wide_range_query_threshold": 4 * time.Hour},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != panel.ID {
		t.Fatalf("expected finding for %s, got %#v", panel.ID, findings)
	}
}

func assertFindingForResourceType(t *testing.T, findings []model.Finding, findingType, resourceID string) {
	t.Helper()
	for _, finding := range findings {
		if finding.Type == findingType && finding.Resource.ID == resourceID {
			return
		}
	}
	t.Fatalf("expected %s finding for %s", findingType, resourceID)
}
