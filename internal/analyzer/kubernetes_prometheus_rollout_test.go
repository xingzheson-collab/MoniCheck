package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusRolloutAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := prometheusRolloutResource("invalid", "Prometheus")
	invalid.Metadata["prometheus_min_ready_seconds_declared"] = "true"
	invalid.Metadata["prometheus_min_ready_seconds_valid"] = "false"
	unisolated := prometheusRolloutResource("unisolated", "PrometheusAgent")
	unisolated.Metadata["prometheus_ha_scheduling_isolation"] = "false"
	daemon := prometheusRolloutResource("daemon", "PrometheusAgent")
	daemon.Metadata["prometheus_rollout_applicable"] = "false"
	daemon.Metadata["prometheus_ha_scheduling_isolation"] = "false"
	for _, resource := range []model.Resource{invalid, unisolated, daemon} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidPrometheusRolloutConfigurationAnalyzer(), invalid.ID},
		{NewKubernetesPrometheusHAWithoutSchedulingIsolationAnalyzer(), unisolated.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func prometheusRolloutResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_rollout_metadata": "true", "prometheus_rollout_applicable": "true", "prometheus_desired_pod_count": "3", "prometheus_min_ready_seconds_declared": "true", "prometheus_min_ready_seconds_valid": "true", "prometheus_min_ready_seconds": "30", "prometheus_scheduling_invalid_setting_count": "0", "prometheus_ha_scheduling_isolation": "true"}}
}
