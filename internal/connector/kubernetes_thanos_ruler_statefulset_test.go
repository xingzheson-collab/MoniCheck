package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerStatefulSetStrategy(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: defaults, namespace: monitoring}
spec: {replicas: 3}
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: risky, namespace: monitoring}
spec:
  replicas: 4
  podManagementPolicy: OrderedReady
  updateStrategy:
    type: RollingUpdate
    rollingUpdate: {maxUnavailable: 50%}
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid, namespace: monitoring}
spec:
  replicas: 2
  podManagementPolicy: Invalid
  updateStrategy:
    type: OnDelete
    rollingUpdate: {partition: 1, maxUnavailable: 0}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	defaults := resources["monitoring/defaults"]
	if defaults.Metadata["thanos_ruler_pod_management_policy"] != "Parallel" || defaults.Metadata["thanos_ruler_update_strategy_type"] != "RollingUpdate" || defaults.Metadata["thanos_ruler_effective_max_unavailable"] != "1" {
		t.Fatalf("unexpected defaults metadata: %#v", defaults.Metadata)
	}
	risky := resources["monitoring/risky"]
	if risky.Metadata["thanos_ruler_pod_management_policy"] != "OrderedReady" || risky.Metadata["thanos_ruler_max_unavailable_percent"] != "true" || risky.Metadata["thanos_ruler_effective_max_unavailable"] != "2" {
		t.Fatalf("unexpected risky metadata: %#v", risky.Metadata)
	}
	invalid := resources["monitoring/invalid"]
	if invalid.Metadata["thanos_ruler_update_strategy_invalid_setting_count"] != "2" {
		t.Fatalf("unexpected invalid metadata: %#v", invalid.Metadata)
	}
}
