package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerImageAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	pinned := alertmanagerImageResource("pinned")
	invalid := alertmanagerImageResource("invalid")
	invalid.Metadata["alertmanager_image_invalid_setting_count"] = "2"
	legacy := alertmanagerImageResource("legacy")
	legacy.Metadata["alertmanager_legacy_image_field_count"] = "2"
	mutable := alertmanagerImageResource("mutable")
	mutable.Metadata["alertmanager_image_digest_pinned"] = "false"
	mutable.Metadata["alertmanager_image_latest_tag"] = "true"
	pullNever := alertmanagerImageResource("pull-never")
	pullNever.Metadata["alertmanager_image_pull_policy_valid"] = "true"
	pullNever.Metadata["alertmanager_image_pull_policy"] = "Never"
	for _, resource := range []model.Resource{pinned, invalid, legacy, mutable, pullNever} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidAlertmanagerImageAnalyzer(), invalid.ID},
		{NewKubernetesDeprecatedAlertmanagerImageFieldsAnalyzer(), legacy.ID},
		{NewKubernetesMutableAlertmanagerImageAnalyzer(), mutable.ID},
		{NewKubernetesAlertmanagerImagePullNeverAnalyzer(), pullNever.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerImageResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_image_metadata": "true", "alertmanager_image_invalid_setting_count": "0", "alertmanager_image_declared": "true", "alertmanager_image_valid": "true", "alertmanager_image_digest_pinned": "true", "alertmanager_image_latest_tag": "false", "alertmanager_legacy_image_field_count": "0", "alertmanager_shadowed_legacy_image_field_count": "0", "alertmanager_image_pull_policy_valid": "true", "alertmanager_image_pull_policy": "IfNotPresent"}}
}
