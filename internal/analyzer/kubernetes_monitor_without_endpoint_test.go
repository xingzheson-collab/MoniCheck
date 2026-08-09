package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesMonitorWithoutEndpointAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	withEndpoint := kubernetesMonitorWithEndpointResource("monitor-api", "api-monitor", "prod", "ServiceMonitor", "1")
	withoutEndpoint := kubernetesMonitorWithEndpointResource("monitor-billing", "billing-monitor", "prod", "ServiceMonitor", "0")
	missingEndpointMetadata := kubernetesMonitorWithEndpointResource("monitor-worker", "worker-monitor", "prod", "PodMonitor", "")
	prometheusTarget := model.Resource{ID: "prom-target", Type: model.ResourceTypeTarget, Name: "api:9090", Status: model.ResourceStatusActive, Source: model.SourceInfo{System: "prometheus"}}

	for _, resource := range []model.Resource{withEndpoint, withoutEndpoint, missingEndpointMetadata, prometheusTarget} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewKubernetesMonitorWithoutEndpointAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(findings), findings)
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
		if finding.Severity != model.SeverityCritical || finding.Category != model.FindingCategoryConfiguration {
			t.Fatalf("expected critical configuration finding, got %#v", finding)
		}
	}
	if !found[withoutEndpoint.ID] || !found[missingEndpointMetadata.ID] || found[withEndpoint.ID] || found[prometheusTarget.ID] {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func kubernetesMonitorWithEndpointResource(id string, name string, namespace string, kind string, endpointCount string) model.Resource {
	resource := kubernetesMonitorResource(id, name, namespace, kind)
	resource.Metadata["endpoint_count"] = endpointCount
	return resource
}
