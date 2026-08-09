package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerPlacementAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := alertmanagerPlacementResource("invalid")
	invalid.Metadata["alertmanager_toleration_invalid_setting_count"] = "2"
	broad := alertmanagerPlacementResource("broad")
	broad.Metadata["alertmanager_broad_toleration_count"] = "1"
	indefinite := alertmanagerPlacementResource("indefinite")
	indefinite.Metadata["alertmanager_indefinite_no_execute_toleration_count"] = "1"
	custom := alertmanagerPlacementResource("custom")
	custom.Metadata["alertmanager_scheduler_name_valid"] = "true"
	custom.Metadata["alertmanager_custom_scheduler"] = "true"
	for _, resource := range []model.Resource{invalid, broad, indefinite, custom} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidAlertmanagerPlacementAnalyzer(), invalid.ID},
		{NewKubernetesAlertmanagerBroadTolerationAnalyzer(), broad.ID},
		{NewKubernetesAlertmanagerIndefiniteNoExecuteTolerationAnalyzer(), indefinite.ID},
		{NewKubernetesAlertmanagerCustomSchedulerAnalyzer(), custom.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerPlacementResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_placement_metadata": "true", "alertmanager_node_selector_declared": "false", "alertmanager_node_selector_valid": "false", "alertmanager_scheduler_name_declared": "false", "alertmanager_scheduler_name_valid": "false", "alertmanager_custom_scheduler": "false", "alertmanager_priority_class_name_declared": "false", "alertmanager_priority_class_name_valid": "false", "alertmanager_toleration_invalid_setting_count": "0", "alertmanager_broad_toleration_count": "0", "alertmanager_indefinite_no_execute_toleration_count": "0"}}
}
