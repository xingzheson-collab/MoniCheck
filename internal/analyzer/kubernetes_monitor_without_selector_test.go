package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesMonitorWithoutSelectorAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	withSelector := kubernetesMonitorWithSelectorResource("monitor-api", "api-monitor", "prod", "ServiceMonitor", "app=api")
	withoutSelector := kubernetesMonitorWithSelectorResource("monitor-billing", "billing-monitor", "prod", "ServiceMonitor", "")
	podMonitorWithoutSelector := kubernetesMonitorWithSelectorResource("monitor-worker", "worker-monitor", "prod", "PodMonitor", "")
	prometheusTarget := model.Resource{ID: "prom-target", Type: model.ResourceTypeTarget, Name: "api:9090", Status: model.ResourceStatusActive, Source: model.SourceInfo{System: "prometheus"}}

	for _, resource := range []model.Resource{withSelector, withoutSelector, podMonitorWithoutSelector, prometheusTarget} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewKubernetesMonitorWithoutSelectorAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(findings), findings)
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
		if finding.Severity != model.SeverityWarning || finding.Category != model.FindingCategoryConfiguration {
			t.Fatalf("expected warning configuration finding, got %#v", finding)
		}
	}
	if !found[withoutSelector.ID] || !found[podMonitorWithoutSelector.ID] || found[withSelector.ID] || found[prometheusTarget.ID] {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func kubernetesMonitorWithSelectorResource(id string, name string, namespace string, kind string, selector string) model.Resource {
	resource := kubernetesMonitorResource(id, name, namespace, kind)
	resource.Metadata["selector"] = selector
	resource.Metadata["endpoint_count"] = "1"
	return resource
}
