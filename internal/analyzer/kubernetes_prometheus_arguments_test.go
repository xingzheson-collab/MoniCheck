package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusArgumentsAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	features := prometheusArgumentsResource("features", "Prometheus")
	features.Metadata["prometheus_feature_count"] = "2"
	invalidFeatures := prometheusArgumentsResource("invalid-features", "PrometheusAgent")
	invalidFeatures.Metadata["prometheus_feature_invalid_count"] = "1"
	invalidFeatures.Metadata["prometheus_feature_duplicate_count"] = "1"
	args := prometheusArgumentsResource("args", "PrometheusAgent")
	args.Metadata["prometheus_additional_arg_count"] = "2"
	invalidArgs := prometheusArgumentsResource("invalid-args", "Prometheus")
	invalidArgs.Metadata["prometheus_additional_arg_invalid_count"] = "1"
	invalidArgs.Metadata["prometheus_additional_arg_duplicate_count"] = "1"
	for _, resource := range []model.Resource{features, invalidFeatures, args, invalidArgs} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		severity model.Severity
	}{
		{NewKubernetesPrometheusFeaturesEnabledAnalyzer(), features.ID, model.SeverityWarning},
		{NewKubernetesInvalidPrometheusFeatureSetAnalyzer(), invalidFeatures.ID, model.SeverityCritical},
		{NewKubernetesPrometheusAdditionalArgsAnalyzer(), args.ID, model.SeverityWarning},
		{NewKubernetesInvalidPrometheusAdditionalArgsAnalyzer(), invalidArgs.ID, model.SeverityCritical},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != test.severity {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func prometheusArgumentsResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_argument_metadata": "true", "prometheus_feature_count": "0", "prometheus_feature_invalid_count": "0", "prometheus_feature_duplicate_count": "0", "prometheus_additional_arg_count": "0", "prometheus_additional_arg_invalid_count": "0", "prometheus_additional_arg_duplicate_count": "0"}}
}
