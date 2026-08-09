package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerArgumentsAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	used := thanosRulerArgumentsResource("used")
	invalid := thanosRulerArgumentsResource("invalid")
	invalid.Metadata["thanos_ruler_additional_arg_count"] = "0"
	invalid.Metadata["thanos_ruler_additional_arg_invalid_count"] = "2"
	invalid.Metadata["thanos_ruler_additional_arg_duplicate_count"] = "1"
	features := thanosRulerArgumentsResource("features")
	features.Metadata["thanos_ruler_additional_arg_count"] = "0"
	features.Metadata["thanos_ruler_feature_count"] = "2"
	invalidFeatures := thanosRulerArgumentsResource("invalid-features")
	invalidFeatures.Metadata["thanos_ruler_additional_arg_count"] = "0"
	invalidFeatures.Metadata["thanos_ruler_feature_invalid_count"] = "1"
	unsupportedFeatures := thanosRulerArgumentsResource("unsupported-features")
	unsupportedFeatures.Metadata["thanos_ruler_additional_arg_count"] = "0"
	unsupportedFeatures.Metadata["thanos_ruler_feature_version_unsupported"] = "true"
	for _, resource := range []model.Resource{used, invalid, features, invalidFeatures, unsupportedFeatures} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesThanosRulerAdditionalArgsAnalyzer(), used.ID},
		{NewKubernetesInvalidThanosRulerAdditionalArgsAnalyzer(), invalid.ID},
		{NewKubernetesThanosRulerFeaturesEnabledAnalyzer(), features.ID},
		{NewKubernetesInvalidThanosRulerFeatureSetAnalyzer(), invalidFeatures.ID},
		{NewKubernetesUnsupportedThanosRulerFeatureVersionAnalyzer(), unsupportedFeatures.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerArgumentsResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_version": "v0.38.0", "thanos_ruler_argument_metadata": "true", "thanos_ruler_feature_count": "0", "thanos_ruler_feature_invalid_count": "0", "thanos_ruler_feature_duplicate_count": "0", "thanos_ruler_feature_version_unsupported": "false", "thanos_ruler_additional_arg_count": "2", "thanos_ruler_additional_arg_invalid_count": "0", "thanos_ruler_additional_arg_duplicate_count": "0"}}
}
