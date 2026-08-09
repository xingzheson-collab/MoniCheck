package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsPrometheusArguments(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: arguments, namespace: monitoring}
spec:
  mode: DaemonSet
  remoteWrite: [{url: https://metrics.example.invalid/api/v1/write}]
  enableFeatures: [feature-a, feature-b]
  additionalArgs:
    - {name: web.enable-lifecycle, value: "true"}
    - {name: storage.agent.retention.max-time, value: 2h}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/arguments"]
	expected := map[string]string{"prometheus_feature_count": "2", "prometheus_feature_invalid_count": "0", "prometheus_feature_duplicate_count": "0", "prometheus_additional_arg_count": "2", "prometheus_additional_arg_invalid_count": "0", "prometheus_additional_arg_duplicate_count": "0"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
	for key, value := range resource.Metadata {
		if strings.Contains(value, "feature-a") || strings.Contains(value, "web.enable") || strings.Contains(value, "retention.max") {
			t.Fatalf("argument detail persisted in %s=%q", key, value)
		}
	}
}

func TestKubernetesManifestConnectorRejectsInvalidPrometheusArguments(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: invalid, namespace: monitoring}
spec:
  enableFeatures: [feature-a, feature-a, ""]
  additionalArgs:
    - {name: web.enable-lifecycle}
    - {name: web.enable-lifecycle}
    - {value: missing-name}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["prometheus_feature_invalid_count"] != "1" || resource.Metadata["prometheus_feature_duplicate_count"] != "1" || resource.Metadata["prometheus_additional_arg_invalid_count"] != "1" || resource.Metadata["prometheus_additional_arg_duplicate_count"] != "1" {
		t.Fatalf("unexpected argument metadata: %#v", resource.Metadata)
	}
}
