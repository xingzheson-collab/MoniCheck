package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerImageAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	pinned := thanosRulerImageResource("pinned")
	invalid := thanosRulerImageResource("invalid")
	invalid.Metadata["thanos_ruler_image_invalid_setting_count"] = "2"
	invalid.Metadata["thanos_ruler_unsupported_legacy_image_field_count"] = "1"
	mutable := thanosRulerImageResource("mutable")
	mutable.Metadata["thanos_ruler_image_digest_pinned"] = "false"
	mutable.Metadata["thanos_ruler_image_latest_tag"] = "true"
	pullNever := thanosRulerImageResource("pull-never")
	pullNever.Metadata["thanos_ruler_image_pull_policy"] = "Never"
	for _, resource := range []model.Resource{pinned, invalid, mutable, pullNever} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		severity model.Severity
	}{
		{NewKubernetesInvalidThanosRulerImageAnalyzer(), invalid.ID, model.SeverityCritical},
		{NewKubernetesMutableThanosRulerImageAnalyzer(), mutable.ID, model.SeverityWarning},
		{NewKubernetesThanosRulerImagePullNeverAnalyzer(), pullNever.ID, model.SeverityWarning},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != test.severity {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerImageResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_image_metadata": "true", "thanos_ruler_image_declared": "true", "thanos_ruler_image_valid": "true", "thanos_ruler_image_digest_pinned": "true", "thanos_ruler_image_latest_tag": "false", "thanos_ruler_image_pull_policy_valid": "true", "thanos_ruler_image_pull_policy": "IfNotPresent", "thanos_ruler_unsupported_legacy_image_field_count": "0", "thanos_ruler_image_invalid_setting_count": "0"}}
}
