package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsPrometheusRuntime(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: runtime, namespace: monitoring}
spec:
  mode: DaemonSet
  remoteWrite: [{url: https://metrics.example.invalid/api/v1/write}]
  listenLocal: true
  logLevel: debug
  logFormat: json
  containers:
    - {name: prometheus, image: quay.io/prometheus/prometheus:v3.0.0}
    - {name: auth-proxy, image: proxy.example.invalid/auth:v1}
  initContainers:
    - {name: init-config-reloader, image: reloader.example.invalid/reloader:v1}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/runtime"]
	expected := map[string]string{"prometheus_listen_local_enabled": "true", "prometheus_log_level": "debug", "prometheus_log_format": "json", "prometheus_sidecar_container_count": "1", "prometheus_container_invalid_count": "0", "prometheus_managed_container_override_count": "1", "prometheus_managed_init_container_override_count": "1", "prometheus_init_container_invalid_count": "0"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
	for key, value := range resource.Metadata {
		if strings.Contains(value, "auth-proxy") || strings.Contains(value, "proxy.example.invalid") || strings.Contains(value, "quay.io") || strings.Contains(value, "init-config-reloader") || strings.Contains(value, "reloader.example.invalid") {
			t.Fatalf("runtime detail persisted in %s=%q", key, value)
		}
	}
}

func TestKubernetesManifestConnectorRejectsInvalidPrometheusRuntime(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: invalid, namespace: monitoring}
spec:
  listenLocal: sometimes
  logLevel: verbose
  logFormat: text
  containers:
    - {image: proxy.example.invalid/auth:v1}
  initContainers:
    - invalid
    - {name: duplicate}
    - {name: duplicate}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["prometheus_listen_local_valid"] != "false" || resource.Metadata["prometheus_log_level_valid"] != "false" || resource.Metadata["prometheus_log_format_valid"] != "false" || resource.Metadata["prometheus_container_invalid_count"] != "1" || resource.Metadata["prometheus_init_container_invalid_count"] != "2" {
		t.Fatalf("unexpected runtime metadata: %#v", resource.Metadata)
	}
}
