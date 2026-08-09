package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesMonitorWithoutMatchedServiceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	matchedService := kubernetesServiceResource("service-api", "api", "prod")
	matchedMonitor := kubernetesMonitorWithSelectorResource("monitor-api", "api-monitor", "prod", "ServiceMonitor", "app=api")
	unmatchedMonitor := kubernetesMonitorWithSelectorResource("monitor-billing", "billing-monitor", "prod", "ServiceMonitor", "app=billing")
	withoutSelector := kubernetesMonitorWithSelectorResource("monitor-empty", "empty-monitor", "prod", "ServiceMonitor", "")
	prometheusTarget := model.Resource{ID: "prom-target", Type: model.ResourceTypeTarget, Name: "api:9090", Status: model.ResourceStatusActive, Source: model.SourceInfo{System: "prometheus"}}

	for _, resource := range []model.Resource{matchedService, matchedMonitor, unmatchedMonitor, withoutSelector, prometheusTarget} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID:     "monitor-service",
		FromID: matchedMonitor.ID,
		ToID:   matchedService.ID,
		Type:   model.RelationshipReferences,
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewKubernetesMonitorWithoutMatchedServiceAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Resource.ID != unmatchedMonitor.ID || findings[0].Severity != model.SeverityWarning || findings[0].Category != model.FindingCategoryReliability {
		t.Fatalf("expected unmatched monitor warning, got %#v", findings[0])
	}
}
