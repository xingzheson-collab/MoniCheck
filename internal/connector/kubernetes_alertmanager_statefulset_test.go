package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsAlertmanagerStatefulSetStrategy(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: rolling, namespace: monitoring}
spec:
  replicas: 3
  podManagementPolicy: OrderedReady
  updateStrategy:
    type: RollingUpdate
    rollingUpdate: {maxUnavailable: "50%"}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/rolling"]
	expected := map[string]string{
		"alertmanager_pod_management_policy":                 "OrderedReady",
		"alertmanager_update_strategy_type":                  "RollingUpdate",
		"alertmanager_max_unavailable":                       "50",
		"alertmanager_max_unavailable_percent":               "true",
		"alertmanager_max_unavailable_valid":                 "true",
		"alertmanager_effective_max_unavailable":             "2",
		"alertmanager_update_strategy_invalid_setting_count": "0",
	}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedAlertmanagerStatefulSetStrategy(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: invalid, namespace: monitoring}
spec:
  podManagementPolicy: Serial
  updateStrategy:
    type: RollingUpdate
    rollingUpdate: {partition: 1, maxUnavailable: 0}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["alertmanager_update_strategy_invalid_setting_count"] != "3" {
		t.Fatalf("unexpected StatefulSet strategy metadata: %#v", resource.Metadata)
	}
}
