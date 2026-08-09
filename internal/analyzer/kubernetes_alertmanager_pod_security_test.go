package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerPodSecurityAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	secure := alertmanagerPodSecurityResource("secure")
	invalid := alertmanagerPodSecurityResource("invalid")
	invalid.Metadata["alertmanager_security_context_invalid_count"] = "2"
	privileged := alertmanagerPodSecurityResource("privileged")
	privileged.Metadata["alertmanager_root_user_context_count"] = "1"
	privileged.Metadata["alertmanager_privileged_container_count"] = "1"
	weak := alertmanagerPodSecurityResource("weak")
	weak.Metadata["alertmanager_privilege_escalation_context_count"] = "1"
	weak.Metadata["alertmanager_unconfined_seccomp_context_count"] = "1"
	for _, resource := range []model.Resource{secure, invalid, privileged, weak} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidAlertmanagerPodSecurityAnalyzer(), invalid.ID},
		{NewKubernetesPrivilegedAlertmanagerWorkloadAnalyzer(), privileged.ID},
		{NewKubernetesWeakAlertmanagerSecurityControlsAnalyzer(), weak.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerPodSecurityResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_pod_security_metadata": "true", "alertmanager_security_context_invalid_count": "0", "alertmanager_root_user_context_count": "0", "alertmanager_non_root_disabled_context_count": "0", "alertmanager_privileged_container_count": "0", "alertmanager_host_process_context_count": "0", "alertmanager_privilege_escalation_context_count": "0", "alertmanager_unconfined_seccomp_context_count": "0", "alertmanager_capability_addition_context_count": "0", "alertmanager_writable_root_filesystem_context_count": "0"}}
}
