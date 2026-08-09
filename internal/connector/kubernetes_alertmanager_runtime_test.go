package connector

import (
	"testing"

	"gopkg.in/yaml.v3"
	"monicheck/internal/model"
)

func TestPopulateKubernetesAlertmanagerRuntimeMetadata(t *testing.T) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(`spec:
  listenLocal: true
  logLevel: debug
  logFormat: json
  containers:
    - name: alertmanager
      resources: {}
    - name: auth-proxy
      image: proxy:latest
  initContainers:
    - name: init-config-reloader
      image: reloader:latest
`), &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	object := kubernetesObject{}
	populateKubernetesAlertmanagerRuntimeObject(&object, yamlMappingValue(document.Content[0], "spec"))
	resource := model.Resource{Metadata: map[string]string{}}
	populateKubernetesAlertmanagerRuntimeMetadata(&resource, object)
	expected := map[string]string{
		"alertmanager_listen_local_enabled":                  "true",
		"alertmanager_log_level":                             "debug",
		"alertmanager_log_format":                            "json",
		"alertmanager_sidecar_container_count":               "1",
		"alertmanager_container_invalid_count":               "0",
		"alertmanager_managed_container_override_count":      "1",
		"alertmanager_managed_init_container_override_count": "1",
		"alertmanager_init_container_invalid_count":          "0",
	}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got metadata %#v", key, value, resource.Metadata)
		}
	}
}

func TestPopulateKubernetesAlertmanagerRuntimeRejectsInvalidSettings(t *testing.T) {
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(`spec:
  listenLocal: enabled
  logLevel: verbose
  logFormat: text
  containers:
    - {}
    - invalid
  initContainers:
    - {}
`), &document); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	object := kubernetesObject{}
	populateKubernetesAlertmanagerRuntimeObject(&object, yamlMappingValue(document.Content[0], "spec"))
	if object.AlertmanagerListenLocalValid || object.AlertmanagerLogLevelValid || object.AlertmanagerLogFormatValid || object.AlertmanagerContainerInvalidCount != 2 || object.AlertmanagerInitContainerInvalidCount != 1 {
		t.Fatalf("unexpected invalid runtime metadata: %#v", object)
	}
}
