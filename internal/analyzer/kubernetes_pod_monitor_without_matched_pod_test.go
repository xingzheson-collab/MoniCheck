package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPodMonitorWithoutMatchedPodAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	matchedPod := kubernetesPodResource("pod-worker", "worker-0", "prod")
	matchedMonitor := kubernetesMonitorWithSelectorResource("monitor-worker", "worker-monitor", "prod", "PodMonitor", "app=worker")
	unmatchedMonitor := kubernetesMonitorWithSelectorResource("monitor-jobs", "jobs-monitor", "prod", "PodMonitor", "app=jobs")
	serviceMonitor := kubernetesMonitorWithSelectorResource("monitor-service", "service-monitor", "prod", "ServiceMonitor", "app=jobs")

	for _, resource := range []model.Resource{matchedPod, matchedMonitor, unmatchedMonitor, serviceMonitor} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID:     "monitor-pod",
		FromID: matchedMonitor.ID,
		ToID:   matchedPod.ID,
		Type:   model.RelationshipReferences,
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewKubernetesPodMonitorWithoutMatchedPodAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Resource.ID != unmatchedMonitor.ID || findings[0].Severity != model.SeverityWarning || findings[0].Category != model.FindingCategoryReliability {
		t.Fatalf("expected unmatched pod monitor warning, got %#v", findings[0])
	}
}

func kubernetesPodResource(id string, name string, namespace string) model.Resource {
	return model.Resource{
		ID:     id,
		Type:   model.ResourceTypeInstance,
		Name:   namespace + "/" + name,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "kubernetes", Instance: "/etc/kubernetes/monitors.yaml", ExternalID: "Pod:" + namespace + "/" + name},
		Metadata: map[string]string{
			"kubernetes_kind": "Pod",
			"namespace":       namespace,
		},
	}
}
