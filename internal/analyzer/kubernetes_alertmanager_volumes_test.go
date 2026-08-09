package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerVolumeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := alertmanagerVolumeResource("invalid")
	invalid.Metadata["alertmanager_volume_invalid_setting_count"] = "2"
	hostPath := alertmanagerVolumeResource("host-path")
	hostPath.Metadata["alertmanager_host_path_volume_count"] = "1"
	hostPath.Metadata["alertmanager_writable_host_path_mount_count"] = "1"
	bidirectional := alertmanagerVolumeResource("bidirectional")
	bidirectional.Metadata["alertmanager_bidirectional_mount_count"] = "1"
	for _, resource := range []model.Resource{invalid, hostPath, bidirectional} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidAlertmanagerVolumeConfigurationAnalyzer(), invalid.ID},
		{NewKubernetesAlertmanagerHostPathVolumeAnalyzer(), hostPath.ID},
		{NewKubernetesAlertmanagerBidirectionalMountAnalyzer(), bidirectional.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerVolumeResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_volume_metadata": "true", "alertmanager_volume_invalid_setting_count": "0", "alertmanager_host_path_volume_count": "0", "alertmanager_writable_host_path_mount_count": "0", "alertmanager_bidirectional_mount_count": "0"}}
}
