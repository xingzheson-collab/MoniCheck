package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsAlertmanagerPodReferences(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: references, namespace: monitoring}
spec:
  secrets: [alertmanager-tls, webhook-token]
  configMaps: [notification-templates]
  serviceAccountName: alertmanager-runtime
  volumes:
    - name: secret-alertmanager-tls
      emptyDir: {}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/references"]
	expected := map[string]string{"alertmanager_secret_count": "2", "alertmanager_config_map_count": "1", "alertmanager_custom_service_account": "true", "alertmanager_pod_reference_invalid_setting_count": "0", "alertmanager_generated_volume_collision_count": "1"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
	for key, value := range resource.Metadata {
		if strings.Contains(value, "alertmanager-tls") || strings.Contains(value, "webhook-token") || strings.Contains(value, "notification-templates") || strings.Contains(value, "alertmanager-runtime") {
			t.Fatalf("Pod reference detail persisted in %s=%q", key, value)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedAlertmanagerPodReferences(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: invalid, namespace: monitoring}
spec:
  secrets: [valid-secret, valid-secret, "Invalid Secret", ""]
  configMaps: configured
  serviceAccountName: "Invalid Account"
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["alertmanager_secret_count"] != "1" || resource.Metadata["alertmanager_pod_reference_invalid_setting_count"] != "4" || resource.Metadata["alertmanager_service_account_name_valid"] != "false" {
		t.Fatalf("unexpected Pod reference metadata: %#v", resource.Metadata)
	}
}
