package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestServiceObservabilityGapAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{ID: "service-api", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive},
		{ID: "service-worker", Type: model.ResourceTypeService, Name: "worker", Status: model.ResourceStatusActive},
		{ID: "service-empty", Type: model.ResourceTypeService, Name: "empty", Status: model.ResourceStatusActive},
		{ID: "service-old", Type: model.ResourceTypeService, Name: "old", Status: model.ResourceStatusDeprecated},
		{ID: "metric-api", Type: model.ResourceTypeMetric, Name: "api_requests_total", Status: model.ResourceStatusActive},
		{ID: "dashboard-api", Type: model.ResourceTypeDashboard, Name: "API Overview", Status: model.ResourceStatusActive},
		{ID: "metric-worker", Type: model.ResourceTypeMetric, Name: "worker_jobs_total", Status: model.ResourceStatusActive},
		{ID: "alert-global", Type: model.ResourceTypeAlertRule, Name: "GlobalAlert", Status: model.ResourceStatusActive},
		{ID: "trace-global", Type: model.ResourceTypeTraceOperation, Name: "global GET", Status: model.ResourceStatusActive},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, relationship := range []model.Relationship{
		{ID: "api-metric", FromID: "metric-api", ToID: "service-api", Type: model.RelationshipBelongsTo},
		{ID: "api-dashboard", FromID: "dashboard-api", ToID: "service-api", Type: model.RelationshipBelongsTo},
		{ID: "worker-metric", FromID: "metric-worker", ToID: "service-worker", Type: model.RelationshipBelongsTo},
	} {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewServiceObservabilityGapAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected worker and empty service findings, got %#v", findings)
	}
	byResource := make(map[string]model.Finding)
	for _, finding := range findings {
		byResource[finding.Resource.ID] = finding
	}
	if byResource["service-worker"].Metadata["observed_signals"] != "metrics" || byResource["service-worker"].Metadata["missing_signals"] != "dashboards,alerts,traces" {
		t.Fatalf("unexpected worker signal evidence: %#v", byResource["service-worker"])
	}
	if byResource["service-empty"].Metadata["signal_count"] != "0" || byResource["service-api"].ID != "" {
		t.Fatalf("unexpected service findings: %#v", byResource)
	}
}

func TestServiceObservabilityGapAnalyzerUsesConfiguredMinimum(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		{ID: "service-api", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive},
		{ID: "metric-api", Type: model.ResourceTypeMetric, Name: "api_requests_total", Status: model.ResourceStatusActive},
		{ID: "dashboard-api", Type: model.ResourceTypeDashboard, Name: "API Overview", Status: model.ResourceStatusActive},
		{ID: "alert-global", Type: model.ResourceTypeAlertRule, Name: "GlobalAlert", Status: model.ResourceStatusActive},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, relationship := range []model.Relationship{
		{ID: "api-metric", FromID: "metric-api", ToID: "service-api", Type: model.RelationshipBelongsTo},
		{ID: "api-dashboard", FromID: "dashboard-api", ToID: "service-api", Type: model.RelationshipBelongsTo},
	} {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewServiceObservabilityGapAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"service_observability_minimum_signals": 3},
	})
	if err != nil || len(findings) != 1 || findings[0].Metadata["minimum_signal_count"] != "3" {
		t.Fatalf("expected configured minimum to find two-of-three coverage, findings=%#v err=%v", findings, err)
	}
}

func TestServiceObservabilityGapAnalyzerSkipsSingleSignalEnvironment(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		{ID: "service-api", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive},
		{ID: "metric-api", Type: model.ResourceTypeMetric, Name: "api_requests_total", Status: model.ResourceStatusActive},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewServiceObservabilityGapAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected single-signal environment to be skipped, findings=%#v err=%v", findings, err)
	}
}
