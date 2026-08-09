package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerPlacementAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := thanosRulerPlacementResource("invalid")
	invalid.Metadata["thanos_ruler_toleration_invalid_setting_count"] = "2"
	broad := thanosRulerPlacementResource("broad")
	broad.Metadata["thanos_ruler_broad_toleration_count"] = "1"
	indefinite := thanosRulerPlacementResource("indefinite")
	indefinite.Metadata["thanos_ruler_indefinite_no_execute_toleration_count"] = "1"
	custom := thanosRulerPlacementResource("custom")
	custom.Metadata["thanos_ruler_scheduler_name_valid"] = "true"
	custom.Metadata["thanos_ruler_custom_scheduler"] = "true"
	for _, resource := range []model.Resource{invalid, broad, indefinite, custom} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidThanosRulerPlacementAnalyzer(), invalid.ID},
		{NewKubernetesThanosRulerBroadTolerationAnalyzer(), broad.ID},
		{NewKubernetesThanosRulerIndefiniteNoExecuteTolerationAnalyzer(), indefinite.ID},
		{NewKubernetesThanosRulerCustomSchedulerAnalyzer(), custom.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerPlacementResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_placement_metadata": "true", "thanos_ruler_node_selector_declared": "false", "thanos_ruler_node_selector_valid": "false", "thanos_ruler_scheduler_name_declared": "false", "thanos_ruler_scheduler_name_valid": "false", "thanos_ruler_custom_scheduler": "false", "thanos_ruler_priority_class_name_declared": "false", "thanos_ruler_priority_class_name_valid": "false", "thanos_ruler_toleration_invalid_setting_count": "0", "thanos_ruler_broad_toleration_count": "0", "thanos_ruler_indefinite_no_execute_toleration_count": "0"}}
}
