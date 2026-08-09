package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesThanosRulerVolumeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := thanosRulerVolumeResource("invalid")
	invalid.Metadata["thanos_ruler_volume_invalid_setting_count"] = "2"
	hostPath := thanosRulerVolumeResource("host-path")
	hostPath.Metadata["thanos_ruler_host_path_volume_count"] = "1"
	hostPath.Metadata["thanos_ruler_writable_host_path_mount_count"] = "1"
	bidirectional := thanosRulerVolumeResource("bidirectional")
	bidirectional.Metadata["thanos_ruler_bidirectional_mount_count"] = "1"
	for _, resource := range []model.Resource{invalid, hostPath, bidirectional} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidThanosRulerVolumeConfigurationAnalyzer(), invalid.ID},
		{NewKubernetesThanosRulerHostPathVolumeAnalyzer(), hostPath.ID},
		{NewKubernetesThanosRulerBidirectionalMountAnalyzer(), bidirectional.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func thanosRulerVolumeResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "ThanosRuler", "namespace": "monitoring", "thanos_ruler_volume_metadata": "true", "thanos_ruler_volume_invalid_setting_count": "0", "thanos_ruler_host_path_volume_count": "0", "thanos_ruler_writable_host_path_mount_count": "0", "thanos_ruler_bidirectional_mount_count": "0"}}
}
