package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsPrometheusRollout(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: isolated, namespace: monitoring}
spec:
  replicas: 3
  minReadySeconds: 30
  affinity:
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        - topologyKey: kubernetes.io/hostname
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: DoNotSchedule
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/isolated"]
	expected := map[string]string{"prometheus_rollout_applicable": "true", "prometheus_min_ready_seconds": "30", "prometheus_pod_anti_affinity_term_count": "1", "prometheus_topology_spread_count": "1", "prometheus_ha_scheduling_isolation": "true", "prometheus_scheduling_invalid_setting_count": "0"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorRejectsInvalidPrometheusRollout(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: invalid, namespace: monitoring}
spec:
  remoteWrite: [{url: https://metrics.example.invalid/api/v1/write}]
  minReadySeconds: -1
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution: invalid
  topologySpreadConstraints:
    - {maxSkew: 0, topologyKey: "", whenUnsatisfiable: Never}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["prometheus_min_ready_seconds_valid"] != "false" || resource.Metadata["prometheus_scheduling_invalid_setting_count"] != "2" {
		t.Fatalf("unexpected rollout metadata: %#v", resource.Metadata)
	}
}

func TestKubernetesManifestConnectorMarksDaemonSetAgentRolloutInapplicable(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
metadata: {name: daemon, namespace: monitoring}
spec:
  mode: DaemonSet
  remoteWrite: [{url: https://metrics.example.invalid/api/v1/write}]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/daemon"]
	if resource.Metadata["prometheus_rollout_applicable"] != "false" {
		t.Fatalf("unexpected DaemonSet rollout metadata: %#v", resource.Metadata)
	}
}
