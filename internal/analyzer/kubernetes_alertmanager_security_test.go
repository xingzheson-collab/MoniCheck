package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerSecurityAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	safe := alertmanagerSecurityResource("safe")
	exposed := alertmanagerSecurityResource("exposed")
	exposed.Metadata["alertmanager_host_network_enabled"] = "true"
	exposed.Metadata["alertmanager_automount_token_declared"] = "true"
	exposed.Metadata["alertmanager_automount_token_valid"] = "true"
	exposed.Metadata["alertmanager_automount_token_enabled"] = "true"
	ha := alertmanagerSecurityResource("ha")
	ha.Metadata["alertmanager_replicas"] = "3"
	incomplete := alertmanagerSecurityResource("incomplete")
	incomplete.Metadata["alertmanager_cluster_tls_declared"] = "true"
	incomplete.Metadata["alertmanager_cluster_tls_invalid_setting_count"] = "1"
	unsupported := alertmanagerSecurityResource("unsupported")
	unsupported.Metadata["alertmanager_cluster_tls_declared"] = "true"
	unsupported.Metadata["alertmanager_cluster_tls_complete"] = "true"
	unsupported.Metadata["alertmanager_cluster_tls_version_unsupported"] = "true"
	for _, resource := range []model.Resource{safe, exposed, ha, incomplete, unsupported} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		severity model.Severity
	}{
		{NewKubernetesAlertmanagerHostNetworkAnalyzer(), exposed.ID, model.SeverityWarning},
		{NewKubernetesAlertmanagerAutomountTokenAnalyzer(), exposed.ID, model.SeverityWarning},
		{NewKubernetesAlertmanagerHAWithoutClusterTLSAnalyzer(), ha.ID, model.SeverityWarning},
		{NewKubernetesInvalidAlertmanagerSecurityAnalyzer(), incomplete.ID, model.SeverityCritical},
		{NewKubernetesUnsupportedAlertmanagerClusterTLSVersionAnalyzer(), unsupported.ID, model.SeverityCritical},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != test.severity {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerSecurityResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_version": "v0.23.0", "alertmanager_replicas": "1", "alertmanager_security_metadata": "true", "alertmanager_host_network_declared": "false", "alertmanager_host_network_valid": "false", "alertmanager_host_network_enabled": "false", "alertmanager_automount_token_declared": "false", "alertmanager_automount_token_valid": "false", "alertmanager_automount_token_enabled": "false", "alertmanager_cluster_tls_declared": "false", "alertmanager_cluster_tls_complete": "false", "alertmanager_cluster_tls_invalid_setting_count": "0", "alertmanager_cluster_tls_version_unsupported": "false"}}
}
