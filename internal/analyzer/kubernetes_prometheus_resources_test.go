package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusResourceAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	bounded := prometheusResourceRequirementsResource("bounded", "Prometheus")
	invalid := prometheusResourceRequirementsResource("invalid", "PrometheusAgent")
	invalid.Metadata["prometheus_resource_invalid_setting_count"] = "2"
	missingRequests := prometheusResourceRequirementsResource("missing-requests", "Prometheus")
	missingRequests.Metadata["prometheus_cpu_request_positive"] = "false"
	missingLimit := prometheusResourceRequirementsResource("missing-limit", "PrometheusAgent")
	missingLimit.Metadata["prometheus_memory_limit_positive"] = "false"
	wrongKind := prometheusResourceRequirementsResource("wrong-kind", "Alertmanager")
	for _, resource := range []model.Resource{bounded, invalid, missingRequests, missingLimit, wrongKind} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		severity model.Severity
	}{
		{NewKubernetesInvalidPrometheusResourcesAnalyzer(), invalid.ID, model.SeverityCritical},
		{NewKubernetesPrometheusWithoutResourceRequestsAnalyzer(), missingRequests.ID, model.SeverityWarning},
		{NewKubernetesPrometheusWithoutMemoryLimitAnalyzer(), missingLimit.ID, model.SeverityWarning},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != test.severity {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func prometheusResourceRequirementsResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_resource_metadata": "true", "prometheus_resource_invalid_setting_count": "0", "prometheus_cpu_request_positive": "true", "prometheus_memory_request_positive": "true", "prometheus_memory_limit_positive": "true"}}
}
