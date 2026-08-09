package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsPrometheusPVCRetention(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: disposable-pvc, namespace: monitoring}
spec:
  storage:
    volumeClaimTemplate:
      spec: {resources: {requests: {storage: 100Gi}}}
  persistentVolumeClaimRetentionPolicy:
    whenDeleted: Delete
    whenScaled: Retain
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/disposable-pvc"]
	expected := map[string]string{"prometheus_storage_mode": "pvc", "prometheus_pvc_retention_applicable": "true", "prometheus_pvc_when_deleted": "Delete", "prometheus_pvc_when_scaled": "Retain", "prometheus_pvc_retention_invalid_setting_count": "0"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedPrometheusPVCRetention(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: invalid-pvc-policy, namespace: monitoring}
spec:
  remoteWrite: [{url: https://metrics.example.invalid/api/v1/write}]
  persistentVolumeClaimRetentionPolicy:
    whenDeleted: Archive
    whenScaled: [Delete]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid-pvc-policy"]
	if resource.Metadata["prometheus_pvc_retention_invalid_setting_count"] != "2" || resource.Metadata["prometheus_pvc_retention_applicable"] != "true" {
		t.Fatalf("unexpected PVC retention metadata: %#v", resource.Metadata)
	}
}

func TestKubernetesManifestConnectorRejectsDaemonSetAgentPVCRetention(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: daemon-pvc-policy, namespace: monitoring}
spec:
  mode: DaemonSet
  remoteWrite: [{url: https://metrics.example.invalid/api/v1/write}]
  persistentVolumeClaimRetentionPolicy: {whenDeleted: Delete}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/daemon-pvc-policy"]
	if resource.Metadata["prometheus_pvc_retention_applicable"] != "false" || resource.Metadata["prometheus_pvc_retention_invalid_setting_count"] != "1" {
		t.Fatalf("unexpected DaemonSet PVC retention metadata: %#v", resource.Metadata)
	}
}
