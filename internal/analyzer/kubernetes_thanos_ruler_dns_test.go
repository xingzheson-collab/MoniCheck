package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerDNSAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	valid := thanosRulerDNSResource("valid")
	invalid := thanosRulerDNSResource("invalid")
	invalid.Metadata["thanos_ruler_dns_invalid_setting_count"] = "2"
	invalid.Metadata["thanos_ruler_host_network_unsupported"] = "true"
	serviceLinks := thanosRulerDNSResource("service-links")
	serviceLinks.Metadata["thanos_ruler_service_links_declared"] = "true"
	serviceLinks.Metadata["thanos_ruler_service_links_enabled"] = "true"
	for _, resource := range []model.Resource{valid, invalid, serviceLinks} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		severity model.Severity
	}{
		{NewKubernetesInvalidThanosRulerDNSAnalyzer(), invalid.ID, model.SeverityCritical},
		{NewKubernetesThanosRulerServiceLinksEnabledAnalyzer(), serviceLinks.ID, model.SeverityWarning},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != test.severity {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerDNSResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_dns_metadata": "true", "thanos_ruler_dns_invalid_setting_count": "0", "thanos_ruler_dns_policy": "ClusterFirst", "thanos_ruler_service_links_declared": "false", "thanos_ruler_service_links_enabled": "false", "thanos_ruler_host_network_unsupported": "false"}}
}
