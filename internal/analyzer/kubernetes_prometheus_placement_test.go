package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusPlacementAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := prometheusPlacementResource("invalid", "Prometheus")
	invalid.Metadata["prometheus_toleration_invalid_setting_count"] = "2"
	broad := prometheusPlacementResource("broad", "PrometheusAgent")
	broad.Metadata["prometheus_broad_toleration_count"] = "1"
	indefinite := prometheusPlacementResource("indefinite", "Prometheus")
	indefinite.Metadata["prometheus_indefinite_no_execute_toleration_count"] = "1"
	custom := prometheusPlacementResource("custom", "PrometheusAgent")
	custom.Metadata["prometheus_scheduler_name_valid"] = "true"
	custom.Metadata["prometheus_custom_scheduler"] = "true"
	for _, resource := range []model.Resource{invalid, broad, indefinite, custom} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidPrometheusPlacementAnalyzer(), invalid.ID},
		{NewKubernetesPrometheusBroadTolerationAnalyzer(), broad.ID},
		{NewKubernetesPrometheusIndefiniteNoExecuteTolerationAnalyzer(), indefinite.ID},
		{NewKubernetesPrometheusCustomSchedulerAnalyzer(), custom.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func prometheusPlacementResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_placement_metadata": "true", "prometheus_node_selector_declared": "false", "prometheus_node_selector_valid": "false", "prometheus_scheduler_name_declared": "false", "prometheus_scheduler_name_valid": "false", "prometheus_custom_scheduler": "false", "prometheus_priority_class_name_declared": "false", "prometheus_priority_class_name_valid": "false", "prometheus_toleration_invalid_setting_count": "0", "prometheus_broad_toleration_count": "0", "prometheus_indefinite_no_execute_toleration_count": "0"}}
}
