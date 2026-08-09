package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsAlertmanagerPVCRetention(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: disposable-pvc, namespace: monitoring}
spec:
  storage:
    volumeClaimTemplate:
      spec: {resources: {requests: {storage: 10Gi}}}
  persistentVolumeClaimRetentionPolicy:
    whenDeleted: Delete
    whenScaled: Retain
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/disposable-pvc"]
	expected := map[string]string{"alertmanager_storage_mode": "pvc", "alertmanager_pvc_when_deleted": "Delete", "alertmanager_pvc_when_scaled": "Retain", "alertmanager_pvc_retention_invalid_setting_count": "0"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedAlertmanagerPVCRetention(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: invalid-pvc-policy, namespace: monitoring}
spec:
  persistentVolumeClaimRetentionPolicy:
    whenDeleted: Archive
    whenScaled: [Delete]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid-pvc-policy"]
	if resource.Metadata["alertmanager_pvc_retention_invalid_setting_count"] != "2" {
		t.Fatalf("unexpected PVC retention metadata: %#v", resource.Metadata)
	}
}
