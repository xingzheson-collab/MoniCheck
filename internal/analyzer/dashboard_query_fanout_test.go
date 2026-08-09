package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDashboardQueryFanoutAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	dashboard := model.Resource{
		ID:     "dashboard-api",
		Type:   model.ResourceTypeDashboard,
		Name:   "API Overview",
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "dashboard:api"},
		Status: model.ResourceStatusActive,
	}
	sampleDashboard := model.Resource{
		ID:     "dashboard-sample",
		Type:   model.ResourceTypeDashboard,
		Name:   "Sample",
		Source: model.SourceInfo{System: "sample", Instance: "local", ExternalID: "dashboard:sample"},
		Status: model.ResourceStatusActive,
	}
	panels := []model.Resource{
		queryPanel("panel-1", "Request Rate", "sum(rate(http_requests_total[5m]))", model.ResourceStatusActive),
		queryPanel("panel-2", "Error Rate", "sum(rate(http_errors_total[5m]))", model.ResourceStatusActive),
		queryPanel("panel-3", "Latency", "histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))", model.ResourceStatusActive),
		queryPanel("panel-4", "CPU", "sum(rate(node_cpu_seconds_total[5m]))", model.ResourceStatusActive),
		queryPanel("panel-empty", "Notes", "", model.ResourceStatusActive),
		queryPanel("panel-inactive", "Old", "sum(rate(old_metric_total[5m]))", model.ResourceStatusDeprecated),
	}
	resources := []model.Resource{dashboard, sampleDashboard}
	resources = append(resources, panels...)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	relationships := []model.Relationship{
		{ID: "panel-1-belongs", FromID: "panel-1", ToID: dashboard.ID, Type: model.RelationshipBelongsTo},
		{ID: "panel-2-belongs", FromID: "panel-2", ToID: dashboard.ID, Type: model.RelationshipBelongsTo},
		{ID: "panel-3-belongs", FromID: "panel-3", ToID: dashboard.ID, Type: model.RelationshipBelongsTo},
		{ID: "panel-4-belongs", FromID: "panel-4", ToID: dashboard.ID, Type: model.RelationshipBelongsTo},
		{ID: "panel-empty-belongs", FromID: "panel-empty", ToID: dashboard.ID, Type: model.RelationshipBelongsTo},
		{ID: "panel-inactive-belongs", FromID: "panel-inactive", ToID: dashboard.ID, Type: model.RelationshipBelongsTo},
		{ID: "sample-panel-belongs", FromID: "panel-1", ToID: sampleDashboard.ID, Type: model.RelationshipBelongsTo},
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

	findings, err := NewDashboardQueryFanoutAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"dashboard_query_fanout_threshold": 3},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "DashboardQueryFanout" || findings[0].Resource.ID != dashboard.ID {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if findings[0].Metadata["query_panel_count"] != "4" {
		t.Fatalf("expected query panel count metadata, got %#v", findings[0].Metadata)
	}
}

func queryPanel(id string, name string, query string, status model.ResourceStatus) model.Resource {
	return model.Resource{
		ID:     id,
		Type:   model.ResourceTypePanel,
		Name:   name,
		Source: model.SourceInfo{System: "grafana", Instance: "local", ExternalID: "panel:" + id},
		Status: status,
		Metadata: map[string]string{
			model.MetadataPromQL: query,
		},
	}
}
