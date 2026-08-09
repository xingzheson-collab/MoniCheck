package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsPrometheusDNS(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: custom-dns, namespace: monitoring}
spec:
  hostNetwork: true
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
	expected := map[string]string{
		"prometheus_host_network_enabled":      "true",
		"prometheus_dns_policy":                "None",
		"prometheus_dns_nameserver_count":      "1",
		"prometheus_dns_invalid_setting_count": "0",
		"prometheus_service_links_enabled":     "true",
	}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedPrometheusDNS(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: invalid-dns, namespace: monitoring}
spec:
  mode: daemonset
  hostNetwork: enabled
  dnsPolicy: None
  dnsConfig:
    nameservers: [not-an-ip]
    options: [{name: rotate}, {name: rotate}]
  enableServiceLinks: enabled
  remoteWrite:
    - url: https://metrics.example.com/api/v1/write
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid-dns"]
	if resource.Metadata["prometheus_dns_invalid_setting_count"] != "5" {
		t.Fatalf("unexpected DNS metadata: %#v", resource.Metadata)
	}
}

func TestKubernetesManifestConnectorDefaultsHostNetworkPrometheusDNS(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: default-dns, namespace: monitoring}
spec:
  hostNetwork: true
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/default-dns"]
	if resource.Metadata["prometheus_dns_policy_declared"] != "false" || resource.Metadata["prometheus_dns_policy"] != "ClusterFirstWithHostNet" || resource.Metadata["prometheus_dns_invalid_setting_count"] != "0" {
		t.Fatalf("unexpected default DNS metadata: %#v", resource.Metadata)
	}
}
