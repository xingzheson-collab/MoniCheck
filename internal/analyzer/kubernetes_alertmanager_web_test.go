package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerWebAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	bounded := alertmanagerWebResource("bounded")
	noTimeout := alertmanagerWebResource("no-timeout")
	noTimeout.Metadata["alertmanager_web_timeout_enabled"] = "false"
	invalid := alertmanagerWebResource("invalid")
	invalid.Metadata["alertmanager_web_invalid_setting_count"] = "2"
	invalid.Metadata["alertmanager_web_timeout_enabled"] = "false"
	plaintext := alertmanagerWebResource("plaintext")
	plaintext.Metadata["alertmanager_external_url_valid"] = "true"
	plaintext.Metadata["alertmanager_external_url_scheme"] = "http"
	https := alertmanagerWebResource("https")
	https.Metadata["alertmanager_external_url_valid"] = "true"
	https.Metadata["alertmanager_external_url_scheme"] = "https"
	for _, resource := range []model.Resource{bounded, noTimeout, invalid, plaintext, https} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		severity model.Severity
	}{
		{NewKubernetesInvalidAlertmanagerWebConfigurationAnalyzer(), invalid.ID, model.SeverityCritical},
		{NewKubernetesAlertmanagerWebTimeoutDisabledAnalyzer(), noTimeout.ID, model.SeverityWarning},
		{NewKubernetesPlaintextExternalAlertmanagerAnalyzer(), plaintext.ID, model.SeverityCritical},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != test.severity {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerWebResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_web_metadata": "true", "alertmanager_web_invalid_setting_count": "0", "alertmanager_web_timeout_enabled": "true", "alertmanager_external_url_valid": "false", "alertmanager_external_url_scheme": ""}}
}
