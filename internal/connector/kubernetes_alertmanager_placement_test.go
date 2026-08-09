package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsAlertmanagerPlacement(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: placement, namespace: monitoring}
spec:
  nodeSelector:
    topology.kubernetes.io/zone: zone-a
  schedulerName: platform-scheduler
  priorityClassName: monitoring-critical
  tolerations:
    - {operator: Exists, effect: NoSchedule}
    - {key: node.kubernetes.io/unreachable, operator: Exists, effect: NoExecute}
    - {key: dedicated, operator: Equal, value: monitoring, effect: NoExecute, tolerationSeconds: 300}
    - {key: reliability, operator: Gt, value: "900", effect: NoSchedule}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/placement"]
	expected := map[string]string{"alertmanager_node_selector_valid": "true", "alertmanager_node_selector_count": "1", "alertmanager_custom_scheduler": "true", "alertmanager_priority_class_name_valid": "true", "alertmanager_toleration_count": "4", "alertmanager_toleration_invalid_setting_count": "0", "alertmanager_broad_toleration_count": "1", "alertmanager_indefinite_no_execute_toleration_count": "1"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
	for key, value := range resource.Metadata {
		if strings.Contains(value, "zone-a") || strings.Contains(value, "platform-scheduler") || strings.Contains(value, "monitoring-critical") || strings.Contains(value, "unreachable") || strings.Contains(value, "dedicated") || strings.Contains(value, "reliability") {
			t.Fatalf("placement detail persisted in %s=%q", key, value)
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedAlertmanagerPlacement(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: invalid, namespace: monitoring}
spec:
  nodeSelector:
    invalid key: zone-a
  schedulerName: ""
  priorityClassName: "Invalid Priority"
  tolerations:
    - {operator: Equal, effect: NoSchedule}
    - {key: dedicated, operator: Exists, value: forbidden, effect: NoSchedule}
    - {key: dedicated, operator: Equal, effect: Everywhere}
    - {key: dedicated, operator: Equal, effect: NoExecute, tolerationSeconds: -1}
    - {key: reliability, operator: Gt, value: "0900", effect: NoSchedule}
    - {key: dedicated, operator: Equal, effect: NoSchedule, tolerationSeconds: 60}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["alertmanager_node_selector_valid"] != "false" || resource.Metadata["alertmanager_scheduler_name_valid"] != "false" || resource.Metadata["alertmanager_priority_class_name_valid"] != "false" || resource.Metadata["alertmanager_toleration_invalid_setting_count"] != "6" || resource.Metadata["alertmanager_toleration_count"] != "0" {
		t.Fatalf("unexpected placement metadata: %#v", resource.Metadata)
	}
}
