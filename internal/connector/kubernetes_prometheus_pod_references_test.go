package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsPrometheusPodReferences(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: references, namespace: monitoring}
spec:
  secrets: [prometheus-tls, remote-token]
  configMaps: [rule-templates]
  serviceAccountName: prometheus-runtime
  volumes:
    - name: secret-prometheus-tls
      emptyDir: {}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/references"]
	expected := map[string]string{
		"prometheus_secret_count":                        "2",
		"prometheus_config_map_count":                    "1",
		"prometheus_custom_service_account":              "true",
		"prometheus_pod_reference_invalid_setting_count": "0",
		"prometheus_generated_volume_collision_count":    "1",
	}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
	for key, value := range resource.Metadata {
		if strings.Contains(value, "prometheus-tls") || strings.Contains(value, "remote-token") || strings.Contains(value, "rule-templates") || strings.Contains(value, "prometheus-runtime") {
			t.Fatalf("Pod reference detail persisted in %s=%q", key, value)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedPrometheusAgentPodReferences(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: invalid, namespace: monitoring}
spec:
  secrets: [valid-secret, valid-secret, "Invalid Secret", ""]
  configMaps: configured
  serviceAccountName: "Invalid Account"
  remoteWrite:
    - url: https://metrics.example.invalid/api/v1/write
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["prometheus_secret_count"] != "1" || resource.Metadata["prometheus_pod_reference_invalid_setting_count"] != "4" || resource.Metadata["prometheus_service_account_name_valid"] != "false" {
		t.Fatalf("unexpected Pod reference metadata: %#v", resource.Metadata)
	}
}
