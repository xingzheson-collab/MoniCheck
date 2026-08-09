package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsPrometheusTerminationGrace(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: graceful, namespace: monitoring}
spec:
  mode: DaemonSet
  remoteWrite: [{url: https://metrics.example.invalid/api/v1/write}]
  terminationGracePeriodSeconds: 120
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/graceful"]
	expected := map[string]string{"prometheus_termination_grace_declared": "true", "prometheus_termination_grace_valid": "true", "prometheus_termination_grace_seconds": "120"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorRejectsInvalidPrometheusTerminationGrace(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: invalid, namespace: monitoring}
spec:
  terminationGracePeriodSeconds: -1
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["prometheus_termination_grace_declared"] != "true" || resource.Metadata["prometheus_termination_grace_valid"] != "false" {
		t.Fatalf("unexpected termination metadata: %#v", resource.Metadata)
	}
}
