package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerRolloutAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := thanosRulerRolloutResource("invalid")
	invalid.Metadata["thanos_ruler_min_ready_seconds_declared"] = "true"
	invalid.Metadata["thanos_ruler_min_ready_seconds_valid"] = "false"
	unisolated := thanosRulerRolloutResource("unisolated")
	unisolated.Metadata["thanos_ruler_ha_scheduling_isolation"] = "false"
	for _, resource := range []model.Resource{invalid, unisolated} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidThanosRulerRolloutConfigurationAnalyzer(), invalid.ID},
		{NewKubernetesThanosRulerHAWithoutSchedulingIsolationAnalyzer(), unisolated.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerRolloutResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_rollout_metadata": "true", "thanos_ruler_replicas": "3", "thanos_ruler_min_ready_seconds_declared": "true", "thanos_ruler_min_ready_seconds_valid": "true", "thanos_ruler_min_ready_seconds": "30", "thanos_ruler_scheduling_invalid_setting_count": "0", "thanos_ruler_ha_scheduling_isolation": "true"}}
}
