package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerPodCustomizationAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := alertmanagerPodCustomizationResource("invalid")
	invalid.Metadata["alertmanager_pod_customization_invalid_setting_count"] = "2"
	reserved := alertmanagerPodCustomizationResource("reserved")
	reserved.Metadata["alertmanager_reserved_label_override_count"] = "1"
	hostAliases := alertmanagerPodCustomizationResource("host-aliases")
	hostAliases.Metadata["alertmanager_host_alias_count"] = "2"
	hostAliases.Metadata["alertmanager_host_alias_hostname_count"] = "3"
	hostAliases.Metadata["alertmanager_loopback_host_alias_count"] = "1"
	for _, resource := range []model.Resource{invalid, reserved, hostAliases} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidAlertmanagerPodCustomizationAnalyzer(), invalid.ID},
		{NewKubernetesAlertmanagerReservedPodMetadataAnalyzer(), reserved.ID},
		{NewKubernetesAlertmanagerHostAliasesAnalyzer(), hostAliases.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerPodCustomizationResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_pod_customization_metadata": "true", "alertmanager_pod_customization_invalid_setting_count": "0", "alertmanager_reserved_label_override_count": "0", "alertmanager_reserved_annotation_override_count": "0", "alertmanager_host_alias_count": "0", "alertmanager_host_alias_hostname_count": "0", "alertmanager_loopback_host_alias_count": "0"}}
}
