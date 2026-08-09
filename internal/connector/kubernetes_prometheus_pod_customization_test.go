package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsPrometheusPodCustomization(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: customization, namespace: monitoring}
spec:
  mode: DaemonSet
  remoteWrite: [{url: https://metrics.example.invalid/api/v1/write}]
  podMetadata:
    labels:
      prometheus: overridden
      platform.example.com/tier: critical
    annotations:
      kubectl.kubernetes.io/default-container: proxy
      platform.example.com/owner: observability
  hostAliases:
    - ip: 127.0.0.1
      hostnames: [metrics.internal]
    - ip: 10.0.0.10
      hostnames: [write.internal, backup.internal]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/customization"]
	expected := map[string]string{"prometheus_pod_metadata_label_count": "2", "prometheus_pod_metadata_annotation_count": "2", "prometheus_reserved_label_override_count": "1", "prometheus_reserved_annotation_override_count": "1", "prometheus_host_alias_count": "2", "prometheus_host_alias_hostname_count": "3", "prometheus_loopback_host_alias_count": "1", "prometheus_pod_customization_invalid_setting_count": "0"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
	for key, value := range resource.Metadata {
		if strings.Contains(value, "metrics.internal") || strings.Contains(value, "write.internal") || strings.Contains(value, "10.0.0.10") || strings.Contains(value, "platform.example.com") || strings.Contains(value, "observability") {
			t.Fatalf("Pod customization detail persisted in %s=%q", key, value)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedPrometheusPodCustomization(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: invalid, namespace: monitoring}
spec:
  podMetadata:
    labels: invalid
    annotations:
      "invalid key": value
  hostAliases:
    - {ip: not-an-ip, hostnames: [bad.internal]}
    - {ip: 10.0.0.1, hostnames: []}
    - {ip: 10.0.0.2, hostnames: ["Invalid Host"]}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["prometheus_pod_customization_invalid_setting_count"] != "5" || resource.Metadata["prometheus_host_alias_count"] != "0" {
		t.Fatalf("unexpected Pod customization metadata: %#v", resource.Metadata)
	}
}
