package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesNamespaceLabelEnforcementAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		kubernetesNamespaceLabelResource("monitor-gap", model.ResourceTypeTarget, "ServiceMonitor", "2", "1", "0", "1"),
		kubernetesNamespaceLabelResource("monitor-excluded", model.ResourceTypeTarget, "Probe", "1", "0", "1", "0"),
		kubernetesNamespaceLabelResource("monitor-safe", model.ResourceTypeTarget, "PodMonitor", "2", "2", "0", "0"),
		kubernetesNamespaceLabelResource("monitor-local", model.ResourceTypeTarget, "ScrapeConfig", "0", "0", "0", "0"),
		kubernetesNamespaceLabelResource("rule-gap", model.ResourceTypeAlertRule, "PrometheusRule", "3", "2", "0", "1"),
		kubernetesNamespaceLabelResource("rule-excluded", model.ResourceTypeRecordingRule, "PrometheusRule", "2", "1", "1", "0"),
		kubernetesNamespaceLabelResource("rule-safe", model.ResourceTypeAlertRule, "PrometheusRule", "2", "2", "0", "0"),
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	monitorFindings, err := NewKubernetesMonitorNamespaceLabelNotEnforcedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute monitor analyzer: %v", err)
	}
	if len(monitorFindings) != 2 || monitorFindings[0].Category != model.FindingCategorySecurity {
		t.Fatalf("expected two monitor security findings, got %#v", monitorFindings)
	}
	ruleFindings, err := NewKubernetesRuleNamespaceLabelNotEnforcedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute rule analyzer: %v", err)
	}
	if len(ruleFindings) != 2 || ruleFindings[0].Metadata["cross_namespace_count"] == "" {
		t.Fatalf("expected two rule findings with coverage metadata, got %#v", ruleFindings)
	}
}

func kubernetesNamespaceLabelResource(id string, resourceType model.ResourceType, kind string, cross string, enforced string, excluded string, unprotected string) model.Resource {
	prefix := "prometheus"
	if kind == "PrometheusRule" {
		prefix = "rule_evaluator"
	}
	return model.Resource{
		ID: id, UID: id, Type: resourceType, Name: id,
		Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			"kubernetes_kind": kind,
			"namespace":       "tenant",
			prefix + "_cross_namespace_selected_count":    cross,
			prefix + "_namespace_label_enforced_count":    enforced,
			prefix + "_namespace_label_excluded_count":    excluded,
			prefix + "_namespace_label_unprotected_count": unprotected,
		},
	}
}
