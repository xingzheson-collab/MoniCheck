package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerStatefulSetAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	rolling := alertmanagerStatefulSetResource("rolling")
	invalid := alertmanagerStatefulSetResource("invalid")
	invalid.Metadata["alertmanager_update_strategy_invalid_setting_count"] = "1"
	ordered := alertmanagerStatefulSetResource("ordered")
	ordered.Metadata["alertmanager_pod_management_policy"] = "OrderedReady"
	onDelete := alertmanagerStatefulSetResource("on-delete")
	onDelete.Metadata["alertmanager_update_strategy_type"] = "OnDelete"
	highUnavailable := alertmanagerStatefulSetResource("high-unavailable")
	highUnavailable.Metadata["alertmanager_effective_max_unavailable"] = "2"
	for _, resource := range []model.Resource{rolling, invalid, ordered, onDelete, highUnavailable} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidAlertmanagerStatefulSetStrategyAnalyzer(), invalid.ID},
		{NewKubernetesAlertmanagerHAOrderedPodManagementAnalyzer(), ordered.ID},
		{NewKubernetesAlertmanagerOnDeleteUpdateAnalyzer(), onDelete.ID},
		{NewKubernetesAlertmanagerHighUnavailableUpdateAnalyzer(), highUnavailable.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerStatefulSetResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_statefulset_metadata": "true", "alertmanager_replicas": "3", "alertmanager_update_strategy_invalid_setting_count": "0", "alertmanager_pod_management_policy": "Parallel", "alertmanager_update_strategy_type": "RollingUpdate", "alertmanager_max_unavailable_valid": "true", "alertmanager_effective_max_unavailable": "1"}}
}
