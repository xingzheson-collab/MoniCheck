package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsPrometheusVolumes(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: volumes, namespace: monitoring}
spec:
  mode: DaemonSet
  remoteWrite: [{url: https://metrics.example.invalid/api/v1/write}]
  volumes:
    - name: host-data
      hostPath: {path: /var/lib/prometheus}
    - name: scratch
      emptyDir: {}
  volumeMounts:
    - {name: host-data, mountPath: /host-data}
    - {name: scratch, mountPath: /scratch, readOnly: true, mountPropagation: Bidirectional}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/volumes"]
	expected := map[string]string{"prometheus_volume_count": "2", "prometheus_volume_mount_count": "2", "prometheus_host_path_volume_count": "1", "prometheus_writable_host_path_mount_count": "1", "prometheus_bidirectional_mount_count": "1", "prometheus_volume_invalid_setting_count": "0"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
	for key, value := range resource.Metadata {
		if strings.Contains(value, "/var/lib") || strings.Contains(value, "/host-data") || strings.Contains(value, "host-data") {
			t.Fatalf("sensitive volume detail persisted in %s=%q", key, value)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedPrometheusVolumes(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: invalid, namespace: monitoring}
spec:
  volumes:
    - {name: duplicate, emptyDir: {}}
    - {name: duplicate, secret: {}}
    - {name: missing-source}
    - {name: multiple-sources, emptyDir: {}, secret: {}}
    - {name: broken-host, hostPath: {}}
  volumeMounts:
    - {name: duplicate, mountPath: /data}
    - {name: duplicate, mountPath: /data}
    - {name: broken, mountPath: /broken, readOnly: sometimes}
    - {name: propagation, mountPath: /propagation, mountPropagation: Everywhere}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["prometheus_volume_invalid_setting_count"] != "7" || resource.Metadata["prometheus_volume_count"] != "1" || resource.Metadata["prometheus_volume_mount_count"] != "1" {
		t.Fatalf("unexpected volume metadata: %#v", resource.Metadata)
	}
}
