package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerPlacement(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: placement, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
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
	expected := map[string]string{"thanos_ruler_node_selector_valid": "true", "thanos_ruler_node_selector_count": "1", "thanos_ruler_custom_scheduler": "true", "thanos_ruler_priority_class_name_valid": "true", "thanos_ruler_toleration_count": "4", "thanos_ruler_toleration_invalid_setting_count": "0", "thanos_ruler_broad_toleration_count": "1", "thanos_ruler_indefinite_no_execute_toleration_count": "1"}
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

func TestKubernetesManifestConnectorRejectsMalformedThanosRulerPlacement(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
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
	if resource.Metadata["thanos_ruler_node_selector_valid"] != "false" || resource.Metadata["thanos_ruler_scheduler_name_valid"] != "false" || resource.Metadata["thanos_ruler_priority_class_name_valid"] != "false" || resource.Metadata["thanos_ruler_toleration_invalid_setting_count"] != "6" || resource.Metadata["thanos_ruler_toleration_count"] != "0" {
		t.Fatalf("unexpected placement metadata: %#v", resource.Metadata)
	}
}
