package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerDNSAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	safe := alertmanagerDNSResource("safe")
	invalid := alertmanagerDNSResource("invalid")
	invalid.Metadata["alertmanager_dns_invalid_setting_count"] = "2"
	fallback := alertmanagerDNSResource("fallback")
	fallback.Metadata["alertmanager_host_network_enabled"] = "true"
	fallback.Metadata["alertmanager_dns_policy_declared"] = "true"
	fallback.Metadata["alertmanager_dns_policy"] = "ClusterFirst"
	serviceLinks := alertmanagerDNSResource("service-links")
	serviceLinks.Metadata["alertmanager_service_links_declared"] = "true"
	serviceLinks.Metadata["alertmanager_service_links_enabled"] = "true"
	for _, resource := range []model.Resource{safe, invalid, fallback, serviceLinks} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidAlertmanagerDNSAnalyzer(), invalid.ID},
		{NewKubernetesHostNetworkAlertmanagerClusterDNSFallbackAnalyzer(), fallback.ID},
		{NewKubernetesAlertmanagerServiceLinksEnabledAnalyzer(), serviceLinks.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerDNSResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_dns_metadata": "true", "alertmanager_dns_invalid_setting_count": "0", "alertmanager_host_network_enabled": "false", "alertmanager_dns_policy_declared": "false", "alertmanager_dns_policy": "ClusterFirst", "alertmanager_service_links_declared": "false", "alertmanager_service_links_enabled": "false"}}
}
