package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesServiceWithoutMonitorAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	coveredService := kubernetesServiceResource("service-covered", "checkout", "payments")
	uncoveredService := kubernetesServiceResource("service-uncovered", "billing", "payments")
	nonKubernetesService := model.Resource{ID: "service-derived", Type: model.ResourceTypeService, Name: "api", Status: model.ResourceStatusActive, Source: model.SourceInfo{System: "prometheus"}}
	serviceMonitor := kubernetesMonitorResource("monitor-checkout", "checkout-monitor", "payments", "ServiceMonitor")

	for _, resource := range []model.Resource{coveredService, uncoveredService, nonKubernetesService, serviceMonitor} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID:     "monitor-service",
		FromID: serviceMonitor.ID,
		ToID:   coveredService.ID,
		Type:   model.RelationshipReferences,
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewKubernetesServiceWithoutMonitorAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Resource.ID != uncoveredService.ID {
		t.Fatalf("expected uncovered service finding for %s, got %s", uncoveredService.ID, findings[0].Resource.ID)
	}
	if findings[0].Metadata["namespace"] != "payments" {
		t.Fatalf("expected namespace metadata, got %#v", findings[0].Metadata)
	}
}

func kubernetesServiceResource(id string, name string, namespace string) model.Resource {
	return model.Resource{
		ID:     id,
		Type:   model.ResourceTypeService,
		Name:   name,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "kubernetes", Instance: "/etc/kubernetes/monitors.yaml", ExternalID: "Service:" + namespace + "/" + name},
		Metadata: map[string]string{
			"kubernetes_kind": "Service",
			"namespace":       namespace,
		},
	}
}

func kubernetesMonitorResource(id string, name string, namespace string, kind string) model.Resource {
	return model.Resource{
		ID:     id,
		Type:   model.ResourceTypeTarget,
		Name:   name,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "kubernetes", Instance: "/etc/kubernetes/monitors.yaml", ExternalID: kind + ":" + namespace + "/" + name},
		Metadata: map[string]string{
			"kubernetes_kind": kind,
			"namespace":       namespace,
		},
	}
}
