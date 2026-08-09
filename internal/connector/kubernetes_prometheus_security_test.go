package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsPrometheusSecurity(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: exposed, namespace: monitoring}
spec:
  mode: DaemonSet
  hostNetwork: true
  automountServiceAccountToken: true
  remoteWrite: [{url: https://metrics.example.invalid/api/v1/write}]
---
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: invalid, namespace: monitoring}
spec:
  automountServiceAccountToken: enabled
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	exposed := resources["monitoring/exposed"]
	if exposed.Metadata["prometheus_host_network_enabled"] != "true" || exposed.Metadata["prometheus_automount_token_declared"] != "true" || exposed.Metadata["prometheus_automount_token_valid"] != "true" || exposed.Metadata["prometheus_automount_token_enabled"] != "true" {
		t.Fatalf("unexpected exposed security metadata: %#v", exposed.Metadata)
	}
	invalid := resources["monitoring/invalid"]
	if invalid.Metadata["prometheus_automount_token_declared"] != "true" || invalid.Metadata["prometheus_automount_token_valid"] != "false" || invalid.Metadata["prometheus_automount_token_enabled"] != "false" {
		t.Fatalf("unexpected invalid security metadata: %#v", invalid.Metadata)
	}
}

func TestKubernetesManifestConnectorLeavesOmittedPrometheusTokenUnevaluable(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: omitted, namespace: monitoring}
spec: {}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/omitted"]
	if resource.Metadata["prometheus_automount_token_declared"] != "false" || resource.Metadata["prometheus_automount_token_valid"] != "false" || resource.Metadata["prometheus_automount_token_enabled"] != "false" {
		t.Fatalf("unexpected omitted token metadata: %#v", resource.Metadata)
	}
}
