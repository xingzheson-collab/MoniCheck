package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerRollout(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: isolated, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
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
	expected := map[string]string{"thanos_ruler_min_ready_seconds": "30", "thanos_ruler_pod_anti_affinity_term_count": "1", "thanos_ruler_topology_spread_count": "1", "thanos_ruler_ha_scheduling_isolation": "true", "thanos_ruler_scheduling_invalid_setting_count": "0"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorRejectsInvalidThanosRulerRollout(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
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
	if resource.Metadata["thanos_ruler_min_ready_seconds_valid"] != "false" || resource.Metadata["thanos_ruler_scheduling_invalid_setting_count"] != "2" {
		t.Fatalf("unexpected rollout metadata: %#v", resource.Metadata)
	}
}
