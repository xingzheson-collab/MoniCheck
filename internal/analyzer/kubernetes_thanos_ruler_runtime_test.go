package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerRuntimeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := thanosRulerRuntimeResource("invalid")
	invalid.Metadata["thanos_ruler_init_container_invalid_count"] = "1"
	debug := thanosRulerRuntimeResource("debug")
	debug.Metadata["thanos_ruler_log_level_valid"] = "true"
	debug.Metadata["thanos_ruler_log_level"] = "debug"
	override := thanosRulerRuntimeResource("override")
	override.Metadata["thanos_ruler_managed_container_override_count"] = "2"
	override.Metadata["thanos_ruler_managed_init_container_override_count"] = "1"
	for _, resource := range []model.Resource{invalid, debug, override} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		severity model.Severity
	}{
		{NewKubernetesInvalidThanosRulerRuntimeAnalyzer(), invalid.ID, model.SeverityCritical},
		{NewKubernetesThanosRulerDebugLoggingAnalyzer(), debug.ID, model.SeverityWarning},
		{NewKubernetesThanosRulerManagedContainerOverrideAnalyzer(), override.ID, model.SeverityWarning},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != test.severity {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerRuntimeResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_runtime_metadata": "true", "thanos_ruler_listen_local_declared": "false", "thanos_ruler_listen_local_valid": "false", "thanos_ruler_log_level_declared": "false", "thanos_ruler_log_level_valid": "false", "thanos_ruler_log_level": "", "thanos_ruler_log_format_declared": "false", "thanos_ruler_log_format_valid": "false", "thanos_ruler_container_invalid_count": "0", "thanos_ruler_init_container_invalid_count": "0", "thanos_ruler_managed_container_override_count": "0", "thanos_ruler_managed_init_container_override_count": "0"}}
}
