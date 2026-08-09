package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsPrometheusImage(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: pinned, namespace: monitoring}
spec:
  image: quay.io/prometheus/prometheus@sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2
  imagePullPolicy: IfNotPresent
  imagePullSecrets: [{name: registry-credentials}]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/pinned"]
	expected := map[string]string{
		"prometheus_image_valid":                 "true",
		"prometheus_image_digest_pinned":         "true",
		"prometheus_image_pull_policy":           "IfNotPresent",
		"prometheus_image_pull_secret_count":     "1",
		"prometheus_image_invalid_setting_count": "0",
	}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedPrometheusImage(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: invalid, namespace: monitoring}
spec:
  mode: daemonset
  image: INVALID IMAGE
  imagePullPolicy: Sometimes
  baseImage: ""
  imagePullSecrets: [{name: registry}, {name: registry}, {}]
  remoteWrite:
    - url: https://metrics.example.com/api/v1/write
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["prometheus_image_invalid_setting_count"] != "5" || resource.Metadata["prometheus_shadowed_legacy_image_field_count"] != "1" {
		t.Fatalf("unexpected image metadata: %#v", resource.Metadata)
	}
}

func TestKubernetesManifestConnectorMapsPrometheusLegacyImage(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: legacy, namespace: monitoring}
spec:
  baseImage: quay.io/prometheus/prometheus
  tag: v3.5.0
  sha: sha256:45b23dee08af5e43a7fea6c4cf9c25ccf269ee113168c19722f87876677c5cb2
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/legacy"]
	if resource.Metadata["prometheus_legacy_image_field_count"] != "3" || resource.Metadata["prometheus_shadowed_legacy_image_field_count"] != "0" || resource.Metadata["prometheus_image_invalid_setting_count"] != "0" {
		t.Fatalf("unexpected legacy image metadata: %#v", resource.Metadata)
	}
}
