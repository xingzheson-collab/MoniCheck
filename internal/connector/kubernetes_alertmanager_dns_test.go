package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsAlertmanagerDNS(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: custom-dns, namespace: monitoring}
spec:
  dnsPolicy: None
  dnsConfig:
    nameservers: [10.96.0.10]
    searches: [monitoring.svc.cluster.local]
    options: [{name: ndots, value: "5"}]
  enableServiceLinks: true
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/custom-dns"]
	expected := map[string]string{"alertmanager_dns_policy": "None", "alertmanager_dns_nameserver_count": "1", "alertmanager_dns_invalid_setting_count": "0", "alertmanager_service_links_enabled": "true"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedAlertmanagerDNS(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: invalid-dns, namespace: monitoring}
spec:
  dnsPolicy: None
  dnsConfig:
    nameservers: [not-an-ip]
    options: [{name: rotate}, {name: rotate}]
  enableServiceLinks: enabled
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid-dns"]
	if resource.Metadata["alertmanager_dns_invalid_setting_count"] != "4" {
		t.Fatalf("unexpected DNS metadata: %#v", resource.Metadata)
	}
}
