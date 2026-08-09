package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerStorageAndRetention(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: stateful, namespace: monitoring}
spec:
  retention: 15d
  storage:
    volumeClaimTemplate:
      spec:
        resources:
          requests: {storage: 40Gi}
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: stateless, namespace: monitoring}
spec:
  retention: 24h
  remoteWrite:
    - url: https://receive.example/api/v1/receive
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid, namespace: monitoring}
spec:
  retention: 1h30m
  storage:
    emptyDir: {}
    ephemeral: invalid
    volumeClaimTemplate:
      spec:
        resources:
          requests: {storage: nope}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	stateful := resources["monitoring/stateful"]
	if stateful.Metadata["thanos_ruler_storage_mode"] != "pvc" || stateful.Metadata["thanos_ruler_pvc_request_valid"] != "true" || stateful.Metadata["thanos_ruler_pvc_request_bytes"] != "42949672960" || stateful.Metadata["thanos_ruler_retention_valid"] != "true" || stateful.Metadata["thanos_ruler_retention_seconds"] != "1296000" || stateful.Metadata["thanos_ruler_stateless_mode"] != "false" {
		t.Fatalf("unexpected stateful storage metadata: %#v", stateful.Metadata)
	}
	stateless := resources["monitoring/stateless"]
	if stateless.Metadata["thanos_ruler_storage_mode"] != "default-empty-dir" || stateless.Metadata["thanos_ruler_stateless_mode"] != "true" || stateless.Metadata["thanos_ruler_remote_write_count"] != "1" {
		t.Fatalf("unexpected stateless storage metadata: %#v", stateless.Metadata)
	}
	invalid := resources["monitoring/invalid"]
	if invalid.Metadata["thanos_ruler_storage_option_count"] != "3" || invalid.Metadata["thanos_ruler_storage_invalid_setting_count"] != "2" || invalid.Metadata["thanos_ruler_retention_declared"] != "true" || invalid.Metadata["thanos_ruler_retention_valid"] != "false" {
		t.Fatalf("unexpected invalid storage metadata: %#v", invalid.Metadata)
	}
}

func TestKubernetesManifestConnectorRejectsMalformedThanosRulerStorage(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: malformed, namespace: monitoring}
spec:
  storage: invalid
  retention: false
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/malformed"]
	if resource.Metadata["thanos_ruler_storage_object_valid"] != "false" || resource.Metadata["thanos_ruler_storage_invalid_setting_count"] != "1" || resource.Metadata["thanos_ruler_retention_valid"] != "false" {
		t.Fatalf("unexpected malformed storage metadata: %#v", resource.Metadata)
	}
}
