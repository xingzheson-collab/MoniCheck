package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusPodReferenceAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := prometheusPodReferenceResource("invalid", "Prometheus")
	invalid.Metadata["prometheus_pod_reference_invalid_setting_count"] = "2"
	secret := prometheusPodReferenceResource("secret", "PrometheusAgent")
	secret.Metadata["prometheus_secret_count"] = "2"
	collision := prometheusPodReferenceResource("collision", "Prometheus")
	collision.Metadata["prometheus_generated_volume_collision_count"] = "1"
	for _, resource := range []model.Resource{invalid, secret, collision} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidPrometheusPodReferencesAnalyzer(), invalid.ID},
		{NewKubernetesPrometheusAdditionalSecretMountsAnalyzer(), secret.ID},
		{NewKubernetesPrometheusGeneratedVolumeCollisionAnalyzer(), collision.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func TestKubernetesPrometheusPodReferenceAnalyzersSuppressInvalidDependentFindings(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := prometheusPodReferenceResource("invalid", "Prometheus")
	resource.Metadata["prometheus_pod_reference_invalid_setting_count"] = "1"
	resource.Metadata["prometheus_secret_count"] = "2"
	resource.Metadata["prometheus_generated_volume_collision_count"] = "1"
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	for _, candidate := range []Analyzer{NewKubernetesPrometheusAdditionalSecretMountsAnalyzer(), NewKubernetesPrometheusGeneratedVolumeCollisionAnalyzer()} {
		findings, err := candidate.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 0 {
			t.Fatalf("expected %s suppression, got %#v err=%v", candidate.ID(), findings, err)
		}
	}
}

func prometheusPodReferenceResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_pod_reference_metadata": "true", "prometheus_pod_reference_invalid_setting_count": "0", "prometheus_service_account_name_declared": "false", "prometheus_service_account_name_valid": "false", "prometheus_secret_count": "0", "prometheus_generated_volume_collision_count": "0"}}
}
