package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerSecretConfigAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := thanosRulerSecretConfigResource("invalid")
	invalid.Metadata["thanos_ruler_secret_config_invalid_setting_count"] = "3"
	shadowed := thanosRulerSecretConfigResource("shadowed")
	shadowed.Metadata["thanos_ruler_shadowed_secret_config_count"] = "2"
	for _, resource := range []model.Resource{invalid, shadowed} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidThanosRulerSecretConfigAnalyzer(), invalid.ID},
		{NewKubernetesShadowedThanosRulerSecretConfigAnalyzer(), shadowed.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerSecretConfigResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_secret_config_metadata": "true", "thanos_ruler_secret_config_invalid_setting_count": "0", "thanos_ruler_shadowed_secret_config_count": "0"}}
}
