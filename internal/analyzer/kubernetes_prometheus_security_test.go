package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusSecurityAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	exposed := prometheusSecurityResource("exposed", "PrometheusAgent")
	exposed.Metadata["prometheus_host_network_declared"] = "true"
	exposed.Metadata["prometheus_host_network_valid"] = "true"
	exposed.Metadata["prometheus_host_network_enabled"] = "true"
	exposed.Metadata["prometheus_automount_token_declared"] = "true"
	exposed.Metadata["prometheus_automount_token_valid"] = "true"
	exposed.Metadata["prometheus_automount_token_enabled"] = "true"
	invalid := prometheusSecurityResource("invalid", "Prometheus")
	invalid.Metadata["prometheus_automount_token_declared"] = "true"
	for _, resource := range []model.Resource{exposed, invalid} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		severity model.Severity
	}{
		{NewKubernetesPrometheusHostNetworkAnalyzer(), exposed.ID, model.SeverityWarning},
		{NewKubernetesPrometheusAutomountTokenAnalyzer(), exposed.ID, model.SeverityWarning},
		{NewKubernetesInvalidPrometheusAutomountTokenAnalyzer(), invalid.ID, model.SeverityCritical},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != test.severity {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func prometheusSecurityResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_host_network_declared": "false", "prometheus_host_network_valid": "false", "prometheus_host_network_enabled": "false", "prometheus_automount_token_declared": "false", "prometheus_automount_token_valid": "false", "prometheus_automount_token_enabled": "false"}}
}
