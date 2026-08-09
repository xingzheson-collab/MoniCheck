package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusDNSAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	safe := prometheusDNSResource("safe", "Prometheus")
	invalid := prometheusDNSResource("invalid", "Prometheus")
	invalid.Metadata["prometheus_dns_invalid_setting_count"] = "2"
	fallback := prometheusDNSResource("fallback", "PrometheusAgent")
	fallback.Metadata["prometheus_host_network_enabled"] = "true"
	fallback.Metadata["prometheus_dns_policy_declared"] = "true"
	fallback.Metadata["prometheus_dns_policy"] = "ClusterFirst"
	serviceLinks := prometheusDNSResource("service-links", "Prometheus")
	serviceLinks.Metadata["prometheus_service_links_declared"] = "true"
	serviceLinks.Metadata["prometheus_service_links_enabled"] = "true"
	for _, resource := range []model.Resource{safe, invalid, fallback, serviceLinks} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidPrometheusDNSAnalyzer(), invalid.ID},
		{NewKubernetesHostNetworkPrometheusClusterDNSFallbackAnalyzer(), fallback.ID},
		{NewKubernetesPrometheusServiceLinksEnabledAnalyzer(), serviceLinks.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func prometheusDNSResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_dns_metadata": "true", "prometheus_dns_invalid_setting_count": "0", "prometheus_host_network_enabled": "false", "prometheus_dns_policy_declared": "false", "prometheus_dns_policy": "ClusterFirst", "prometheus_service_links_declared": "false", "prometheus_service_links_enabled": "false"}}
}
