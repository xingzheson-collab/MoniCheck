package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsAlertmanagerResources(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: bounded, namespace: monitoring}
spec:
  resources:
    requests: {cpu: 100m, memory: 128Mi}
    limits: {cpu: "1", memory: 512Mi}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/bounded"]
	for _, key := range []string{"alertmanager_cpu_request_positive", "alertmanager_memory_request_positive", "alertmanager_cpu_limit_positive", "alertmanager_memory_limit_positive"} {
		if resource.Metadata[key] != "true" {
			t.Fatalf("expected %s=true, got %#v", key, resource.Metadata)
		}
	}
	if resource.Metadata["alertmanager_resource_invalid_setting_count"] != "0" {
		t.Fatalf("unexpected resource metadata: %#v", resource.Metadata)
	}
}

func TestKubernetesManifestConnectorRejectsMalformedAlertmanagerResources(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: invalid, namespace: monitoring}
spec:
  resources:
    requests: {cpu: nope, memory: 1Gi}
    limits: {cpu: 500m, memory: 512Mi}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["alertmanager_resource_invalid_setting_count"] != "2" {
		t.Fatalf("expected malformed CPU and request-above-limit counts, got %#v", resource.Metadata)
	}
}
