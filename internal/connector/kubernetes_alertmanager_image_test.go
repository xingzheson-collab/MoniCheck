package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsAlertmanagerImage(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: pinned, namespace: monitoring}
spec:
  image: quay.io/prometheus/alertmanager@sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2
  imagePullPolicy: IfNotPresent
  imagePullSecrets: [{name: registry-credentials}]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/pinned"]
	expected := map[string]string{"alertmanager_image_valid": "true", "alertmanager_image_digest_pinned": "true", "alertmanager_image_pull_policy": "IfNotPresent", "alertmanager_image_pull_secret_count": "1", "alertmanager_image_invalid_setting_count": "0"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedAlertmanagerImage(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: invalid, namespace: monitoring}
spec:
  image: INVALID IMAGE
  imagePullPolicy: Sometimes
  baseImage: ""
  imagePullSecrets: [{name: registry}, {name: registry}, {}]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["alertmanager_image_invalid_setting_count"] != "5" || resource.Metadata["alertmanager_shadowed_legacy_image_field_count"] != "1" {
		t.Fatalf("unexpected image metadata: %#v", resource.Metadata)
	}
}
