package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerLimitsAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	bounded := alertmanagerLimitsResource("bounded", "true", "true", "0", "false")
	unbounded := alertmanagerLimitsResource("unbounded", "false", "false", "0", "false")
	partial := alertmanagerLimitsResource("partial", "true", "false", "0", "false")
	invalid := alertmanagerLimitsResource("invalid", "false", "false", "2", "false")
	unsupported := alertmanagerLimitsResource("unsupported", "true", "true", "0", "true")
	for _, resource := range []model.Resource{bounded, unbounded, partial, invalid, unsupported} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		want     map[string]model.Severity
	}{
		{NewKubernetesUnboundedAlertmanagerSilencesAnalyzer(), map[string]model.Severity{unbounded.ID: model.SeverityWarning, partial.ID: model.SeverityWarning, invalid.ID: model.SeverityWarning}},
		{NewKubernetesInvalidAlertmanagerLimitsAnalyzer(), map[string]model.Severity{invalid.ID: model.SeverityCritical}},
		{NewKubernetesUnsupportedAlertmanagerLimitsVersionAnalyzer(), map[string]model.Severity{unsupported.ID: model.SeverityCritical}},
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

func alertmanagerLimitsResource(name, countEnabled, sizeEnabled, invalidCount, unsupported string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_version": "v0.27.0", "alertmanager_limits_declared": "false", "alertmanager_max_silences_enabled": countEnabled, "alertmanager_max_per_silence_bytes_enabled": sizeEnabled, "alertmanager_limits_invalid_setting_count": invalidCount, "alertmanager_limits_version_unsupported": unsupported}}
}
