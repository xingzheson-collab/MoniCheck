package connector

import (
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestKubernetesManifestConnectorMapsAlertmanagerConfigSourcesAndServices(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: first, namespace: monitoring}
spec:
  configSecret: legacy-config
  alertmanagerConfiguration: {name: global-routing}
  serviceName: shared-alertmanager
  portName: web
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: second, namespace: monitoring}
spec:
  serviceName: shared-alertmanager
---
apiVersion: monitoring.coreos.com/v1beta1
kind: AlertmanagerConfig
metadata: {name: global-routing, namespace: monitoring}
spec:
  route: {receiver: default}
  receivers:
    - name: default
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	first := resources["monitoring/first"]
	second := resources["monitoring/second"]
	if first.Metadata["alertmanager_configuration_found"] != "true" || first.Metadata["alertmanager_config_source_conflict"] != "true" || first.Metadata["alertmanager_shared_service_count"] != "1" {
		t.Fatalf("unexpected first config metadata: %#v", first.Metadata)
	}
	if second.Metadata["alertmanager_configuration_found"] != "false" || second.Metadata["alertmanager_shared_service_count"] != "1" {
		t.Fatalf("unexpected second config metadata: %#v", second.Metadata)
	}
}

func TestPopulateKubernetesAlertmanagerConfigSourceRejectsMalformedSettings(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: invalid, namespace: monitoring}
spec:
  configSecret: {}
  alertmanagerConfiguration: {name: ""}
  serviceName: []
  portName: {}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["alertmanager_config_secret_valid"] != "false" || resource.Metadata["alertmanager_configuration_valid"] != "false" || resource.Metadata["alertmanager_service_name_valid"] != "false" || resource.Metadata["alertmanager_port_name_valid"] != "false" {
		t.Fatalf("unexpected malformed config source metadata: %#v", resource.Metadata)
	}
}

func alertmanagerConfigSourceResourcesByName(resources []model.Resource) map[string]model.Resource {
	result := make(map[string]model.Resource, len(resources))
	for _, resource := range resources {
		result[resource.Name] = resource
	}
	return result
}
