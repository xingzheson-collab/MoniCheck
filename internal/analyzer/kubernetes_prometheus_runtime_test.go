package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusRuntimeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := prometheusRuntimeResource("invalid", "Prometheus")
	invalid.Metadata["prometheus_listen_local_declared"] = "true"
	invalid.Metadata["prometheus_listen_local_valid"] = "false"
	debug := prometheusRuntimeResource("debug", "PrometheusAgent")
	debug.Metadata["prometheus_log_level_valid"] = "true"
	debug.Metadata["prometheus_log_level"] = "debug"
	loopback := prometheusRuntimeResource("loopback", "Prometheus")
	loopback.Metadata["prometheus_listen_local_valid"] = "true"
	loopback.Metadata["prometheus_listen_local_enabled"] = "true"
	loopback.Metadata["prometheus_external_url_valid"] = "true"
	loopback.Metadata["prometheus_external_url_scheme"] = "https"
	proxied := prometheusRuntimeResource("proxied", "Prometheus")
	proxied.Metadata["prometheus_listen_local_valid"] = "true"
	proxied.Metadata["prometheus_listen_local_enabled"] = "true"
	proxied.Metadata["prometheus_external_url_valid"] = "true"
	proxied.Metadata["prometheus_sidecar_container_count"] = "1"
	override := prometheusRuntimeResource("override", "PrometheusAgent")
	override.Metadata["prometheus_managed_container_override_count"] = "2"
	override.Metadata["prometheus_managed_init_container_override_count"] = "1"
	for _, resource := range []model.Resource{invalid, debug, loopback, proxied, override} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidPrometheusRuntimeConfigurationAnalyzer(), invalid.ID},
		{NewKubernetesPrometheusDebugLoggingAnalyzer(), debug.ID},
		{NewKubernetesExternalPrometheusLoopbackOnlyAnalyzer(), loopback.ID},
		{NewKubernetesPrometheusManagedContainerOverrideAnalyzer(), override.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func prometheusRuntimeResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_runtime_metadata": "true", "prometheus_listen_local_declared": "false", "prometheus_listen_local_valid": "false", "prometheus_listen_local_enabled": "false", "prometheus_log_level_declared": "false", "prometheus_log_level_valid": "false", "prometheus_log_level": "", "prometheus_log_format_declared": "false", "prometheus_log_format_valid": "false", "prometheus_container_invalid_count": "0", "prometheus_init_container_invalid_count": "0", "prometheus_managed_container_override_count": "0", "prometheus_managed_init_container_override_count": "0", "prometheus_sidecar_container_count": "0", "prometheus_external_url_valid": "false"}}
}
