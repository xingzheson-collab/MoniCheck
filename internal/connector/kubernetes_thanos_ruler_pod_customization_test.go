package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerPodCustomization(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: customization, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
  podMetadata:
    labels:
      thanos-ruler: overridden
      platform.example.com/tier: critical
    annotations:
      kubectl.kubernetes.io/default-container: proxy
      platform.example.com/owner: observability
  hostAliases:
    - ip: 127.0.0.1
      hostnames: [query.internal]
    - ip: 10.0.0.10
      hostnames: [rules.internal, backup.internal]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/customization"]
	expected := map[string]string{"thanos_ruler_pod_metadata_label_count": "2", "thanos_ruler_pod_metadata_annotation_count": "2", "thanos_ruler_reserved_label_override_count": "1", "thanos_ruler_reserved_annotation_override_count": "1", "thanos_ruler_host_alias_count": "2", "thanos_ruler_host_alias_hostname_count": "3", "thanos_ruler_loopback_host_alias_count": "1", "thanos_ruler_pod_customization_invalid_setting_count": "0"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
	for key, value := range resource.Metadata {
		if strings.Contains(value, "query.internal") || strings.Contains(value, "rules.internal") || strings.Contains(value, "10.0.0.10") || strings.Contains(value, "platform.example.com") || strings.Contains(value, "observability") {
			t.Fatalf("Pod customization detail persisted in %s=%q", key, value)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedThanosRulerPodCustomization(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
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
	if resource.Metadata["thanos_ruler_pod_customization_invalid_setting_count"] != "5" || resource.Metadata["thanos_ruler_host_alias_count"] != "0" {
		t.Fatalf("unexpected Pod customization metadata: %#v", resource.Metadata)
	}
}
