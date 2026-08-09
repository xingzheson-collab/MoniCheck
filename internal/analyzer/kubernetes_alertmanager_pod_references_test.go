package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerPodReferenceAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := alertmanagerPodReferenceResource("invalid")
	invalid.Metadata["alertmanager_pod_reference_invalid_setting_count"] = "2"
	secret := alertmanagerPodReferenceResource("secret")
	secret.Metadata["alertmanager_secret_count"] = "2"
	collision := alertmanagerPodReferenceResource("collision")
	collision.Metadata["alertmanager_generated_volume_collision_count"] = "1"
	for _, resource := range []model.Resource{invalid, secret, collision} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidAlertmanagerPodReferencesAnalyzer(), invalid.ID},
		{NewKubernetesAlertmanagerAdditionalSecretMountsAnalyzer(), secret.ID},
		{NewKubernetesAlertmanagerGeneratedVolumeCollisionAnalyzer(), collision.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerPodReferenceResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_pod_reference_metadata": "true", "alertmanager_pod_reference_invalid_setting_count": "0", "alertmanager_service_account_name_declared": "false", "alertmanager_service_account_name_valid": "false", "alertmanager_secret_count": "0", "alertmanager_generated_volume_collision_count": "0"}}
}
