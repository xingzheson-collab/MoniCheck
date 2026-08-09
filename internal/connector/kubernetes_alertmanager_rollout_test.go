package connector

import (
	"testing"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func TestPopulateKubernetesAlertmanagerRolloutMetadata(t *testing.T) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(`spec:
  minReadySeconds: 30
  affinity:
    podAntiAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        - topologyKey: kubernetes.io/hostname
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: DoNotSchedule
`), &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	object := kubernetesObject{AlertmanagerVersion: "v0.30.0"}
	populateKubernetesAlertmanagerRolloutObject(&object, yamlMappingValue(document.Content[0], "spec"))
	resource := model.Resource{Metadata: map[string]string{}}
	populateKubernetesAlertmanagerRolloutMetadata(&resource, object)
	expected := map[string]string{
		"alertmanager_min_ready_seconds":                "30",
		"alertmanager_dispatch_delay_supported":         "true",
		"alertmanager_pod_anti_affinity_term_count":     "1",
		"alertmanager_topology_spread_count":            "1",
		"alertmanager_ha_scheduling_isolation":          "true",
		"alertmanager_scheduling_invalid_setting_count": "0",
	}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got metadata %#v", key, value, resource.Metadata)
		}
	}
}

func TestPopulateKubernetesAlertmanagerRolloutRejectsInvalidSettings(t *testing.T) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(`spec:
  minReadySeconds: -1
  affinity:
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution: invalid
  topologySpreadConstraints:
    - maxSkew: 0
      topologyKey: ""
      whenUnsatisfiable: Never
`), &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	object := kubernetesObject{AlertmanagerVersion: "v0.29.0"}
	populateKubernetesAlertmanagerRolloutObject(&object, yamlMappingValue(document.Content[0], "spec"))
	if object.AlertmanagerMinReadySecondsValid || object.AlertmanagerSchedulingInvalidSettingCount != 2 || object.AlertmanagerDispatchDelaySupported || !object.AlertmanagerDispatchDelayVersionEvaluable {
		t.Fatalf("unexpected invalid rollout metadata: %#v", object)
	}
}
