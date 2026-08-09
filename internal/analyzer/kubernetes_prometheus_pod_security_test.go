package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusPodSecurityAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	secure := prometheusPodSecurityResource("secure", "Prometheus")
	invalid := prometheusPodSecurityResource("invalid", "PrometheusAgent")
	invalid.Metadata["prometheus_security_context_invalid_count"] = "2"
	privileged := prometheusPodSecurityResource("privileged", "Prometheus")
	privileged.Metadata["prometheus_root_user_context_count"] = "1"
	privileged.Metadata["prometheus_privileged_container_count"] = "1"
	weak := prometheusPodSecurityResource("weak", "PrometheusAgent")
	weak.Metadata["prometheus_privilege_escalation_context_count"] = "1"
	weak.Metadata["prometheus_unconfined_seccomp_context_count"] = "1"
	wrongType := prometheusPodSecurityResource("wrong-type", "Prometheus")
	wrongType.Type = model.ResourceTypeInstance
	for _, resource := range []model.Resource{secure, invalid, privileged, weak, wrongType} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		severity model.Severity
	}{
		{NewKubernetesInvalidPrometheusPodSecurityAnalyzer(), invalid.ID, model.SeverityCritical},
		{NewKubernetesPrivilegedPrometheusWorkloadAnalyzer(), privileged.ID, model.SeverityCritical},
		{NewKubernetesWeakPrometheusSecurityControlsAnalyzer(), weak.ID, model.SeverityWarning},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != test.severity {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func prometheusPodSecurityResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_pod_security_metadata": "true", "prometheus_security_context_invalid_count": "0", "prometheus_root_user_context_count": "0", "prometheus_non_root_disabled_context_count": "0", "prometheus_privileged_container_count": "0", "prometheus_host_process_context_count": "0", "prometheus_privilege_escalation_context_count": "0", "prometheus_unconfined_seccomp_context_count": "0", "prometheus_capability_addition_context_count": "0", "prometheus_writable_root_filesystem_context_count": "0"}}
}
