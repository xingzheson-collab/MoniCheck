package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestServiceWithoutSLOAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{ID: "service-api", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive},
		{ID: "service-worker", Type: model.ResourceTypeService, Name: "worker", Status: model.ResourceStatusActive},
		{ID: "service-trace", Type: model.ResourceTypeService, Name: "trace-only", Status: model.ResourceStatusActive},
		{ID: "metric-api", Type: model.ResourceTypeMetric, Name: "api_requests_total", Status: model.ResourceStatusActive},
		{ID: "metric-worker", Type: model.ResourceTypeMetric, Name: "worker_jobs_total", Status: model.ResourceStatusActive},
		{ID: "trace-operation", Type: model.ResourceTypeTraceOperation, Name: "GET /trace", Status: model.ResourceStatusActive},
		{ID: "slo-api", Type: model.ResourceTypeAlertRule, Name: "APIErrorBudgetBurnRate", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataSLORule: "true", model.MetadataSLOName: "api-availability"}},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, relationship := range []model.Relationship{
		{ID: "api-metric", FromID: "metric-api", ToID: "service-api", Type: model.RelationshipBelongsTo},
		{ID: "api-slo", FromID: "slo-api", ToID: "service-api", Type: model.RelationshipBelongsTo},
		{ID: "api-slo-uses-metric", FromID: "slo-api", ToID: "metric-api", Type: model.RelationshipUses},
		{ID: "worker-metric", FromID: "metric-worker", ToID: "service-worker", Type: model.RelationshipBelongsTo},
		{ID: "trace-operation-service", FromID: "trace-operation", ToID: "service-trace", Type: model.RelationshipBelongsTo},
	} {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewServiceWithoutSLOAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != "service-worker" || findings[0].Metadata["metric_count"] != "1" {
		t.Fatalf("expected only metric-backed worker without SLO, got %#v", findings)
	}

	findings, err = NewServiceWithoutSLOAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"allowed_services_without_slo": []string{"worker"}},
	})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected allowlisted service to be skipped, findings=%#v err=%v", findings, err)
	}
}

func TestServiceWithoutSLOAnalyzerSkipsEnvironmentWithoutActiveSLO(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		{ID: "service-api", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive},
		{ID: "metric-api", Type: model.ResourceTypeMetric, Name: "api_requests_total", Status: model.ResourceStatusActive},
		{ID: "disabled-slo", Type: model.ResourceTypeAlertRule, Name: "APIErrorBudgetBurnRate", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataSLORule: "true", model.MetadataDisabled: "true"}},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{ID: "api-metric", FromID: "metric-api", ToID: "service-api", Type: model.RelationshipBelongsTo}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewServiceWithoutSLOAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected environment without active SLO rules to be skipped, findings=%#v err=%v", findings, err)
	}
}
