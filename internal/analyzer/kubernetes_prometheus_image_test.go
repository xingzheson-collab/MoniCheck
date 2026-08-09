package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusImageAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	pinned := prometheusImageResource("pinned", "Prometheus")
	invalid := prometheusImageResource("invalid", "PrometheusAgent")
	invalid.Metadata["prometheus_image_invalid_setting_count"] = "2"
	legacy := prometheusImageResource("legacy", "Prometheus")
	legacy.Metadata["prometheus_legacy_image_field_count"] = "2"
	mutable := prometheusImageResource("mutable", "Prometheus")
	mutable.Metadata["prometheus_image_digest_pinned"] = "false"
	mutable.Metadata["prometheus_image_latest_tag"] = "true"
	pullNever := prometheusImageResource("pull-never", "PrometheusAgent")
	pullNever.Metadata["prometheus_image_pull_policy_valid"] = "true"
	pullNever.Metadata["prometheus_image_pull_policy"] = "Never"
	for _, resource := range []model.Resource{pinned, invalid, legacy, mutable, pullNever} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidPrometheusImageAnalyzer(), invalid.ID},
		{NewKubernetesDeprecatedPrometheusImageFieldsAnalyzer(), legacy.ID},
		{NewKubernetesMutablePrometheusImageAnalyzer(), mutable.ID},
		{NewKubernetesPrometheusImagePullNeverAnalyzer(), pullNever.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func prometheusImageResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_image_metadata": "true", "prometheus_image_invalid_setting_count": "0", "prometheus_image_declared": "true", "prometheus_image_valid": "true", "prometheus_image_digest_pinned": "true", "prometheus_image_latest_tag": "false", "prometheus_legacy_image_field_count": "0", "prometheus_shadowed_legacy_image_field_count": "0", "prometheus_image_pull_policy_valid": "true", "prometheus_image_pull_policy": "IfNotPresent"}}
}
