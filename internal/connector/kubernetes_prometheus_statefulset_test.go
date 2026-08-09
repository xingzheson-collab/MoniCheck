package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsPrometheusStatefulSetStrategy(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: main, namespace: monitoring}
spec:
  replicas: 4
  podManagementPolicy: OrderedReady
  updateStrategy:
    type: RollingUpdate
    rollingUpdate: {maxUnavailable: "25%"}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: edge, namespace: monitoring}
spec:
  mode: daemonset
  podManagementPolicy: Serial
  updateStrategy: invalid
  remoteWrite:
    - url: https://metrics.example.com/api/v1/write
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	main := resources["monitoring/main"]
	expected := map[string]string{
		"prometheus_statefulset_applicable":                "true",
		"prometheus_pod_management_policy":                 "OrderedReady",
		"prometheus_update_strategy_type":                  "RollingUpdate",
		"prometheus_max_unavailable":                       "25",
		"prometheus_max_unavailable_percent":               "true",
		"prometheus_effective_max_unavailable":             "1",
		"prometheus_update_strategy_invalid_setting_count": "0",
	}
	for key, value := range expected {
		if main.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, main.Metadata)
		}
	}
	edge := resources["monitoring/edge"]
	if edge.Metadata["prometheus_statefulset_applicable"] != "false" || edge.Metadata["prometheus_update_strategy_invalid_setting_count"] != "2" {
		t.Fatalf("unexpected DaemonSet Agent strategy metadata: %#v", edge.Metadata)
	}
}

func TestKubernetesManifestConnectorRejectsPrometheusPartition(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: invalid, namespace: monitoring}
spec:
  updateStrategy:
    type: RollingUpdate
    rollingUpdate: {partition: 1}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["prometheus_update_strategy_invalid_setting_count"] != "1" {
		t.Fatalf("unexpected StatefulSet strategy metadata: %#v", resource.Metadata)
	}
}
