package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerArgumentsAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	clean := alertmanagerArgumentsResource("clean")
	features := alertmanagerArgumentsResource("features")
	features.Metadata["alertmanager_feature_count"] = "2"
	invalidFeatures := alertmanagerArgumentsResource("invalid-features")
	invalidFeatures.Metadata["alertmanager_feature_invalid_count"] = "1"
	invalidFeatures.Metadata["alertmanager_feature_duplicate_count"] = "1"
	oldFeatures := alertmanagerArgumentsResource("old-features")
	oldFeatures.Metadata["alertmanager_feature_count"] = "1"
	oldFeatures.Metadata["alertmanager_feature_version_unsupported"] = "true"
	args := alertmanagerArgumentsResource("args")
	args.Metadata["alertmanager_additional_arg_count"] = "2"
	invalidArgs := alertmanagerArgumentsResource("invalid-args")
	invalidArgs.Metadata["alertmanager_additional_arg_invalid_count"] = "1"
	invalidArgs.Metadata["alertmanager_additional_arg_duplicate_count"] = "1"
	oldArgs := alertmanagerArgumentsResource("old-args")
	oldArgs.Metadata["alertmanager_additional_arg_count"] = "1"
	oldArgs.Metadata["alertmanager_additional_args_version_unsupported"] = "true"
	for _, resource := range []model.Resource{clean, features, invalidFeatures, oldFeatures, args, invalidArgs, oldArgs} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		want     map[string]model.Severity
	}{
		{NewKubernetesAlertmanagerFeaturesEnabledAnalyzer(), map[string]model.Severity{features.ID: model.SeverityWarning, oldFeatures.ID: model.SeverityWarning}},
		{NewKubernetesInvalidAlertmanagerFeatureSetAnalyzer(), map[string]model.Severity{invalidFeatures.ID: model.SeverityCritical}},
		{NewKubernetesUnsupportedAlertmanagerFeatureVersionAnalyzer(), map[string]model.Severity{oldFeatures.ID: model.SeverityCritical}},
		{NewKubernetesAlertmanagerAdditionalArgsAnalyzer(), map[string]model.Severity{args.ID: model.SeverityWarning, oldArgs.ID: model.SeverityWarning}},
		{NewKubernetesInvalidAlertmanagerAdditionalArgsAnalyzer(), map[string]model.Severity{invalidArgs.ID: model.SeverityCritical}},
		{NewKubernetesUnsupportedAlertmanagerAdditionalArgsVersionAnalyzer(), map[string]model.Severity{oldArgs.ID: model.SeverityCritical}},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != len(test.want) {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
		for _, finding := range findings {
			if finding.Severity != test.want[finding.Resource.ID] {
				t.Fatalf("unexpected %s severity for %s: %s", test.analyzer.ID(), finding.Resource.ID, finding.Severity)
			}
		}
	}
}

func alertmanagerArgumentsResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_version": "v0.24.0", "alertmanager_argument_metadata": "true", "alertmanager_feature_count": "0", "alertmanager_feature_invalid_count": "0", "alertmanager_feature_duplicate_count": "0", "alertmanager_feature_version_unsupported": "false", "alertmanager_additional_arg_count": "0", "alertmanager_additional_arg_invalid_count": "0", "alertmanager_additional_arg_duplicate_count": "0", "alertmanager_additional_args_version_unsupported": "false"}}
}
