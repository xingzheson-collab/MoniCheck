package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerPodSecurityAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	secure := thanosRulerPodSecurityResource("secure")
	invalid := thanosRulerPodSecurityResource("invalid")
	invalid.Metadata["thanos_ruler_security_context_invalid_count"] = "2"
	privileged := thanosRulerPodSecurityResource("privileged")
	privileged.Metadata["thanos_ruler_root_user_context_count"] = "1"
	privileged.Metadata["thanos_ruler_privileged_container_count"] = "1"
	weak := thanosRulerPodSecurityResource("weak")
	weak.Metadata["thanos_ruler_privilege_escalation_context_count"] = "1"
	weak.Metadata["thanos_ruler_unconfined_seccomp_context_count"] = "1"
	for _, resource := range []model.Resource{secure, invalid, privileged, weak} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		severity model.Severity
	}{
		{NewKubernetesInvalidThanosRulerPodSecurityAnalyzer(), invalid.ID, model.SeverityCritical},
		{NewKubernetesPrivilegedThanosRulerWorkloadAnalyzer(), privileged.ID, model.SeverityCritical},
		{NewKubernetesWeakThanosRulerSecurityControlsAnalyzer(), weak.ID, model.SeverityWarning},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource || findings[0].Severity != test.severity {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerPodSecurityResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_pod_security_metadata": "true", "thanos_ruler_security_context_invalid_count": "0", "thanos_ruler_root_user_context_count": "0", "thanos_ruler_non_root_disabled_context_count": "0", "thanos_ruler_privileged_container_count": "0", "thanos_ruler_host_process_context_count": "0", "thanos_ruler_privilege_escalation_context_count": "0", "thanos_ruler_unconfined_seccomp_context_count": "0", "thanos_ruler_capability_addition_context_count": "0", "thanos_ruler_writable_root_filesystem_context_count": "0"}}
}
