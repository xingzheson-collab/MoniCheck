package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerRuntime(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: runtime, namespace: monitoring}
spec:
  queryEndpoints: [dnssrv+_http._tcp.thanos-query.monitoring.svc]
  listenLocal: true
  logLevel: debug
  logFormat: json
  containers:
    - {name: thanos-ruler, image: example.invalid/thanos:test}
    - {name: config-reloader, image: example.invalid/reloader:test}
    - {name: auth-proxy, image: example.invalid/proxy:test}
  initContainers:
    - {name: init-config-reloader, image: example.invalid/init:test}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/runtime"]
	expected := map[string]string{"thanos_ruler_listen_local_enabled": "true", "thanos_ruler_log_level": "debug", "thanos_ruler_log_format": "json", "thanos_ruler_sidecar_container_count": "1", "thanos_ruler_managed_container_override_count": "2", "thanos_ruler_managed_init_container_override_count": "1", "thanos_ruler_container_invalid_count": "0", "thanos_ruler_init_container_invalid_count": "0"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
	for key, value := range resource.Metadata {
		if strings.Contains(value, "thanos-ruler") || strings.Contains(value, "config-reloader") || strings.Contains(value, "auth-proxy") || strings.Contains(value, "example.invalid") {
			t.Fatalf("runtime implementation detail persisted in %s=%q", key, value)
		}
	}
}

func TestKubernetesManifestConnectorRejectsInvalidThanosRulerRuntime(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid, namespace: monitoring}
spec:
  queryConfig: {name: query, key: config.yaml}
  listenLocal: enabled
  logLevel: verbose
  logFormat: text
  containers: [{name: duplicate}, {name: duplicate}]
  initContainers: [invalid]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["thanos_ruler_listen_local_valid"] != "false" || resource.Metadata["thanos_ruler_log_level_valid"] != "false" || resource.Metadata["thanos_ruler_log_format_valid"] != "false" || resource.Metadata["thanos_ruler_container_invalid_count"] != "1" || resource.Metadata["thanos_ruler_init_container_invalid_count"] != "1" {
		t.Fatalf("unexpected invalid runtime metadata: %#v", resource.Metadata)
	}
}
