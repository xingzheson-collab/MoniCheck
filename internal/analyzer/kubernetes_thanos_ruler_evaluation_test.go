package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerEvaluationAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := thanosRulerEvaluationResource("invalid")
	invalid.Metadata["thanos_ruler_evaluation_invalid_setting_count"] = "2"
	unsupported := thanosRulerEvaluationResource("unsupported")
	unsupported.Metadata["thanos_ruler_evaluation_unsupported_setting_count"] = "3"
	inconsistent := thanosRulerEvaluationResource("inconsistent")
	inconsistent.Metadata["thanos_ruler_restoration_timing_inconsistent"] = "true"
	for _, resource := range []model.Resource{invalid, unsupported, inconsistent} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidThanosRulerEvaluationAnalyzer(), invalid.ID},
		{NewKubernetesUnsupportedThanosRulerEvaluationAnalyzer(), unsupported.ID},
		{NewKubernetesInconsistentThanosRulerRestorationAnalyzer(), inconsistent.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerEvaluationResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_version": "v0.29.0", "thanos_ruler_evaluation_metadata": "true", "thanos_ruler_evaluation_invalid_setting_count": "0", "thanos_ruler_evaluation_unsupported_setting_count": "0", "thanos_ruler_restoration_timing_inconsistent": "false"}}
}
