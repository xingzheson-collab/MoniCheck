package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerRuntimeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	valid := alertmanagerRuntimeResource("valid")
	invalid := alertmanagerRuntimeResource("invalid")
	invalid.Metadata["alertmanager_log_format_valid"] = "false"
	debug := alertmanagerRuntimeResource("debug")
	debug.Metadata["alertmanager_log_level"] = "debug"
	loopback := alertmanagerRuntimeResource("loopback")
	loopback.Metadata["alertmanager_listen_local_enabled"] = "true"
	loopback.Metadata["alertmanager_sidecar_container_count"] = "0"
	override := alertmanagerRuntimeResource("override")
	override.Metadata["alertmanager_managed_container_override_count"] = "1"
	override.Metadata["alertmanager_managed_init_container_override_count"] = "1"
	for _, resource := range []model.Resource{valid, invalid, debug, loopback, override} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidAlertmanagerRuntimeConfigurationAnalyzer(), invalid.ID},
		{NewKubernetesAlertmanagerDebugLoggingAnalyzer(), debug.ID},
		{NewKubernetesExternalAlertmanagerLoopbackOnlyAnalyzer(), loopback.ID},
		{NewKubernetesAlertmanagerManagedContainerOverrideAnalyzer(), override.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerRuntimeResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_runtime_metadata": "true", "alertmanager_listen_local_declared": "true", "alertmanager_listen_local_valid": "true", "alertmanager_listen_local_enabled": "false", "alertmanager_log_level_declared": "true", "alertmanager_log_level_valid": "true", "alertmanager_log_level": "info", "alertmanager_log_format_declared": "true", "alertmanager_log_format_valid": "true", "alertmanager_log_format": "json", "alertmanager_container_invalid_count": "0", "alertmanager_init_container_invalid_count": "0", "alertmanager_managed_container_override_count": "0", "alertmanager_managed_init_container_override_count": "0", "alertmanager_sidecar_container_count": "1", "alertmanager_external_url_valid": "true", "alertmanager_external_url_scheme": "https"}}
}
