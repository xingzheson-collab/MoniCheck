package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerSecretConfigurationPrecedence(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: shadowed-config, namespace: monitoring}
spec:
  queryEndpoints: [http://legacy-query.monitoring:9090]
  queryConfig: {name: query-private, key: query.yaml}
  alertmanagersUrl: [http://legacy-alertmanager.monitoring:9093]
  alertmanagersConfig: {name: alertmanager-private, key: alertmanager.yaml}
  objectStorageConfig: {name: object-private, key: object.yaml}
  objectStorageConfigFile: /private/object.yaml
  tracingConfig: {name: tracing-private, key: tracing.yaml}
  tracingConfigFile: /private/tracing.yaml
  alertRelabelConfigs: {name: relabel-private, key: relabel.yaml}
  alertRelabelConfigFile: /private/relabel.yaml
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/shadowed-config"]
	expected := map[string]string{"thanos_ruler_secret_config_metadata": "true", "thanos_ruler_secret_selector_declared_count": "5", "thanos_ruler_secret_config_invalid_setting_count": "0", "thanos_ruler_shadowed_secret_config_count": "5", "thanos_ruler_file_config_declared_count": "3"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
	for key, value := range resource.Metadata {
		for _, secret := range []string{"query-private", "alertmanager-private", "object-private", "tracing-private", "relabel-private", "/private/"} {
			if strings.Contains(key, secret) || strings.Contains(value, secret) {
				t.Fatalf("Secret or file identity persisted in %s=%q", key, value)
			}
		}
	}
}

func TestKubernetesManifestConnectorRejectsInvalidThanosRulerSecretConfiguration(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid-config, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
  objectStorageConfig: invalid
  queryConfig: {name: "Invalid Name", key: "", optional: invalid}
  tracingConfigFile: {path: invalid}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid-config"]
	if resource.Metadata["thanos_ruler_secret_selector_declared_count"] != "2" || resource.Metadata["thanos_ruler_secret_config_invalid_setting_count"] != "5" {
		t.Fatalf("unexpected Secret configuration metadata: %#v", resource.Metadata)
	}
}
