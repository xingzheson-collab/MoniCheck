package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesMonitorBroadNamespaceSelectorAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	limited := kubernetesMonitorWithNamespaceSelectorResource("monitor-api", "api-monitor", "monitoring", "ServiceMonitor", "matchNames=prod")
	broad := kubernetesMonitorWithNamespaceSelectorResource("monitor-all", "all-monitor", "monitoring", "ServiceMonitor", "*")
	broad.Metadata["prometheus_selected_count"] = "2"
	broad.Metadata["prometheus_namespace_selector_effective_count"] = "1"
	protected := kubernetesMonitorWithNamespaceSelectorResource("monitor-protected", "protected-monitor", "monitoring", "PodMonitor", "*")
	protected.Metadata["prometheus_selected_count"] = "1"
	protected.Metadata["prometheus_namespace_selector_effective_count"] = "0"
	probe := kubernetesMonitorWithNamespaceSelectorResource("probe-all", "global-probe", "monitoring", "Probe", "*")
	probe.Metadata["prometheus_selected_count"] = "1"
	probe.Metadata["prometheus_namespace_selector_effective_count"] = "1"
	unselected := kubernetesMonitorWithNamespaceSelectorResource("monitor-unselected", "unselected-monitor", "monitoring", "ServiceMonitor", "*")
	unselected.Metadata["prometheus_selected_count"] = "0"
	unselected.Metadata["prometheus_namespace_selector_effective_count"] = "0"
	prometheusTarget := model.Resource{ID: "prom-target", Type: model.ResourceTypeTarget, Name: "api:9090", Status: model.ResourceStatusActive, Source: model.SourceInfo{System: "prometheus"}}

	for _, resource := range []model.Resource{limited, broad, protected, probe, unselected, prometheusTarget} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewKubernetesMonitorBroadNamespaceSelectorAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(findings), findings)
	}
	if findings[0].Resource.ID != broad.ID || findings[0].Severity != model.SeverityWarning || findings[0].Category != model.FindingCategoryConfiguration {
		t.Fatalf("expected broad namespace selector warning, got %#v", findings[0])
	}
	if findings[0].Metadata["selected_workload_count"] != "2" || findings[0].Metadata["effective_workload_count"] != "1" {
		t.Fatalf("expected effective workload coverage metadata, got %#v", findings[0].Metadata)
	}
	if findings[1].Resource.ID != probe.ID {
		t.Fatalf("expected broad Probe warning, got %#v", findings[1])
	}
}

func kubernetesMonitorWithNamespaceSelectorResource(id string, name string, namespace string, kind string, namespaceSelector string) model.Resource {
	resource := kubernetesMonitorWithSelectorResource(id, name, namespace, kind, "app=api")
	resource.Metadata["namespace_selector"] = namespaceSelector
	return resource
}
