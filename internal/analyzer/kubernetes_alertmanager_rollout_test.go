package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerRolloutAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	protected := alertmanagerRolloutResource("protected")
	invalid := alertmanagerRolloutResource("invalid")
	invalid.Metadata["alertmanager_min_ready_seconds_declared"] = "true"
	invalid.Metadata["alertmanager_min_ready_seconds_valid"] = "false"
	unisolated := alertmanagerRolloutResource("unisolated")
	unisolated.Metadata["alertmanager_ha_scheduling_isolation"] = "false"
	noDelay := alertmanagerRolloutResource("no-delay")
	noDelay.Metadata["alertmanager_min_ready_seconds"] = "0"
	for _, resource := range []model.Resource{protected, invalid, unisolated, noDelay} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidAlertmanagerRolloutConfigurationAnalyzer(), invalid.ID},
		{NewKubernetesAlertmanagerHAWithoutSchedulingIsolationAnalyzer(), unisolated.ID},
		{NewKubernetesAlertmanagerHAWithoutRolloutDelayAnalyzer(), noDelay.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerRolloutResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_rollout_metadata": "true", "alertmanager_replicas": "3", "alertmanager_min_ready_seconds_declared": "true", "alertmanager_min_ready_seconds_valid": "true", "alertmanager_min_ready_seconds": "30", "alertmanager_dispatch_delay_version_evaluable": "true", "alertmanager_dispatch_delay_supported": "true", "alertmanager_scheduling_invalid_setting_count": "0", "alertmanager_ha_scheduling_isolation": "true"}}
}
