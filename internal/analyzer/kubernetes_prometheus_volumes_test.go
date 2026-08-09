package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusVolumeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := prometheusVolumeResource("invalid", "Prometheus")
	invalid.Metadata["prometheus_volume_invalid_setting_count"] = "2"
	hostPath := prometheusVolumeResource("host-path", "PrometheusAgent")
	hostPath.Metadata["prometheus_host_path_volume_count"] = "1"
	hostPath.Metadata["prometheus_writable_host_path_mount_count"] = "1"
	bidirectional := prometheusVolumeResource("bidirectional", "Prometheus")
	bidirectional.Metadata["prometheus_bidirectional_mount_count"] = "1"
	for _, resource := range []model.Resource{invalid, hostPath, bidirectional} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidPrometheusVolumeConfigurationAnalyzer(), invalid.ID},
		{NewKubernetesPrometheusHostPathVolumeAnalyzer(), hostPath.ID},
		{NewKubernetesPrometheusBidirectionalMountAnalyzer(), bidirectional.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func prometheusVolumeResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_volume_metadata": "true", "prometheus_volume_invalid_setting_count": "0", "prometheus_host_path_volume_count": "0", "prometheus_writable_host_path_mount_count": "0", "prometheus_bidirectional_mount_count": "0"}}
}
