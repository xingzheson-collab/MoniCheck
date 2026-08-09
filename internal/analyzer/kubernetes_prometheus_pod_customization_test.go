package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusPodCustomizationAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := prometheusPodCustomizationResource("invalid", "Prometheus")
	invalid.Metadata["prometheus_pod_customization_invalid_setting_count"] = "2"
	reserved := prometheusPodCustomizationResource("reserved", "PrometheusAgent")
	reserved.Metadata["prometheus_reserved_label_override_count"] = "1"
	hostAliases := prometheusPodCustomizationResource("host-aliases", "Prometheus")
	hostAliases.Metadata["prometheus_host_alias_count"] = "2"
	hostAliases.Metadata["prometheus_host_alias_hostname_count"] = "3"
	hostAliases.Metadata["prometheus_loopback_host_alias_count"] = "1"
	for _, resource := range []model.Resource{invalid, reserved, hostAliases} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidPrometheusPodCustomizationAnalyzer(), invalid.ID},
		{NewKubernetesPrometheusReservedPodMetadataAnalyzer(), reserved.ID},
		{NewKubernetesPrometheusHostAliasesAnalyzer(), hostAliases.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func prometheusPodCustomizationResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_pod_customization_metadata": "true", "prometheus_pod_customization_invalid_setting_count": "0", "prometheus_reserved_label_override_count": "0", "prometheus_reserved_annotation_override_count": "0", "prometheus_host_alias_count": "0", "prometheus_host_alias_hostname_count": "0", "prometheus_loopback_host_alias_count": "0"}}
}
