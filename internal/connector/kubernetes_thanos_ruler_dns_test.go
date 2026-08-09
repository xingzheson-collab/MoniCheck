package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerDNS(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: custom, namespace: monitoring}
spec:
  dnsPolicy: None
  dnsConfig:
    nameservers: [10.96.0.10]
    searches: [monitoring.svc.cluster.local]
    options: [{name: ndots, value: "2"}]
  enableServiceLinks: true
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: defaults, namespace: monitoring}
spec: {}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	custom := resources["monitoring/custom"]
	if custom.Metadata["thanos_ruler_dns_policy"] != "None" || custom.Metadata["thanos_ruler_dns_nameserver_count"] != "1" || custom.Metadata["thanos_ruler_dns_invalid_setting_count"] != "0" || custom.Metadata["thanos_ruler_service_links_enabled"] != "true" {
		t.Fatalf("unexpected custom DNS metadata: %#v", custom.Metadata)
	}
	defaults := resources["monitoring/defaults"]
	if defaults.Metadata["thanos_ruler_dns_policy"] != "ClusterFirst" || defaults.Metadata["thanos_ruler_dns_policy_declared"] != "false" || defaults.Metadata["thanos_ruler_dns_invalid_setting_count"] != "0" {
		t.Fatalf("unexpected default DNS metadata: %#v", defaults.Metadata)
	}
}

func TestKubernetesManifestConnectorRejectsInvalidThanosRulerDNS(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid, namespace: monitoring}
spec:
  hostNetwork: true
  dnsPolicy: None
  dnsConfig:
    nameservers: [not-an-ip]
    options: [{name: ndots}, {name: ndots}]
  enableServiceLinks: enabled
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["thanos_ruler_host_network_unsupported"] != "true" || resource.Metadata["thanos_ruler_dns_invalid_setting_count"] != "5" {
		t.Fatalf("unexpected invalid DNS metadata: %#v", resource.Metadata)
	}
}
