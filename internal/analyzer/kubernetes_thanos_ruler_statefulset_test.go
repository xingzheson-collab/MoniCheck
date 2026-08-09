package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerStatefulSetAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	valid := thanosRulerStatefulSetResource("valid")
	invalid := thanosRulerStatefulSetResource("invalid")
	invalid.Metadata["thanos_ruler_update_strategy_invalid_setting_count"] = "2"
	ordered := thanosRulerStatefulSetResource("ordered")
	ordered.Metadata["thanos_ruler_pod_management_policy"] = "OrderedReady"
	onDelete := thanosRulerStatefulSetResource("on-delete")
	onDelete.Metadata["thanos_ruler_update_strategy_type"] = "OnDelete"
	highUnavailable := thanosRulerStatefulSetResource("high-unavailable")
	highUnavailable.Metadata["thanos_ruler_effective_max_unavailable"] = "2"
	for _, resource := range []model.Resource{valid, invalid, ordered, onDelete, highUnavailable} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		severity model.Severity
	}{
		{NewKubernetesInvalidThanosRulerStatefulSetStrategyAnalyzer(), invalid.ID, model.SeverityCritical},
		{NewKubernetesThanosRulerHAOrderedPodManagementAnalyzer(), ordered.ID, model.SeverityWarning},
		{NewKubernetesThanosRulerOnDeleteUpdateAnalyzer(), onDelete.ID, model.SeverityWarning},
		{NewKubernetesThanosRulerHighUnavailableUpdateAnalyzer(), highUnavailable.ID, model.SeverityWarning},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != test.severity {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerStatefulSetResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_statefulset_metadata": "true", "thanos_ruler_replicas": "3", "thanos_ruler_update_strategy_invalid_setting_count": "0", "thanos_ruler_pod_management_policy": "Parallel", "thanos_ruler_update_strategy_type": "RollingUpdate", "thanos_ruler_max_unavailable_valid": "true", "thanos_ruler_effective_max_unavailable": "1"}}
}
