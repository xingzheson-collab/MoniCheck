package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerConfigSourceAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	valid := alertmanagerConfigSourceResource("valid")
	invalid := alertmanagerConfigSourceResource("invalid")
	invalid.Metadata["alertmanager_service_name_declared"] = "true"
	invalid.Metadata["alertmanager_service_name_valid"] = "false"
	shadowed := alertmanagerConfigSourceResource("shadowed")
	shadowed.Metadata["alertmanager_config_source_conflict"] = "true"
	missing := alertmanagerConfigSourceResource("missing")
	missing.Metadata["alertmanager_configuration_found"] = "false"
	shared := alertmanagerConfigSourceResource("shared")
	shared.Metadata["alertmanager_shared_service_count"] = "1"
	for _, resource := range []model.Resource{valid, invalid, shadowed, missing, shared} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidAlertmanagerConfigSourceAnalyzer(), invalid.ID},
		{NewKubernetesShadowedAlertmanagerConfigSecretAnalyzer(), shadowed.ID},
		{NewKubernetesMissingAlertmanagerConfigurationAnalyzer(), missing.ID},
		{NewKubernetesSharedAlertmanagerGoverningServiceAnalyzer(), shared.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerConfigSourceResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_config_source_metadata": "true", "alertmanager_config_secret_declared": "false", "alertmanager_config_secret_valid": "false", "alertmanager_configuration_declared": "true", "alertmanager_configuration_valid": "true", "alertmanager_configuration_found": "true", "alertmanager_config_source_conflict": "false", "alertmanager_service_name_declared": "false", "alertmanager_service_name_valid": "false", "alertmanager_port_name_declared": "false", "alertmanager_port_name_valid": "false", "alertmanager_shared_service_count": "0"}}
}
