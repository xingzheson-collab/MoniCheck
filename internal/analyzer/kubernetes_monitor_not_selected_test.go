package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesMonitorNotSelectedAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		kubernetesSelectionTarget("selected", "ServiceMonitor", "true", "1"),
		kubernetesSelectionTarget("unselected", "ServiceMonitor", "true", "0"),
		kubernetesSelectionTarget("unknown", "PodMonitor", "false", "0"),
		kubernetesSelectionTarget("probe", "Probe", "true", "0"),
		kubernetesSelectionTarget("legacy", "ServiceMonitor", "", ""),
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewKubernetesMonitorNotSelectedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 || findings[0].Resource.Name != "probe" || findings[1].Resource.Name != "unselected" {
		t.Fatalf("expected only conclusive unselected targets, got %#v", findings)
	}
	for _, finding := range findings {
		if finding.Severity != model.SeverityWarning || finding.Category != model.FindingCategoryConfiguration {
			t.Fatalf("unexpected finding: %#v", finding)
		}
	}
}

func kubernetesSelectionTarget(name string, kind string, evaluable string, selectedCount string) model.Resource {
	metadata := map[string]string{
		"kubernetes_kind":                kind,
		"namespace":                      "prod",
		"prometheus_selection_candidate": "true",
		"prometheus_selection_evaluable": evaluable,
		"prometheus_selected_count":      selectedCount,
	}
	return model.Resource{
		ID: name, UID: name, Type: model.ResourceTypeTarget, Name: name,
		Source: model.SourceInfo{System: "kubernetes"}, Metadata: metadata, Status: model.ResourceStatusActive,
	}
}
