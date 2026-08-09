package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesMonitorWithoutEndpointPortAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	withPort := kubernetesMonitorWithEndpointPortResource("monitor-api", "api-monitor", "prod", "ServiceMonitor", "1", "port=http")
	withoutPort := kubernetesMonitorWithEndpointPortResource("monitor-billing", "billing-monitor", "prod", "ServiceMonitor", "1", "")
	withoutEndpoint := kubernetesMonitorWithEndpointPortResource("monitor-worker", "worker-monitor", "prod", "PodMonitor", "0", "")
	prometheusTarget := model.Resource{ID: "prom-target", Type: model.ResourceTypeTarget, Name: "api:9090", Status: model.ResourceStatusActive, Source: model.SourceInfo{System: "prometheus"}}

	for _, resource := range []model.Resource{withPort, withoutPort, withoutEndpoint, prometheusTarget} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewKubernetesMonitorWithoutEndpointPortAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Resource.ID != withoutPort.ID || findings[0].Severity != model.SeverityCritical || findings[0].Category != model.FindingCategoryConfiguration {
		t.Fatalf("expected missing endpoint port critical finding, got %#v", findings[0])
	}
}

func kubernetesMonitorWithEndpointPortResource(id string, name string, namespace string, kind string, endpointCount string, endpointPorts string) model.Resource {
	resource := kubernetesMonitorWithSelectorResource(id, name, namespace, kind, "app=api")
	resource.Metadata["endpoint_count"] = endpointCount
	resource.Metadata["endpoint_ports"] = endpointPorts
	return resource
}
