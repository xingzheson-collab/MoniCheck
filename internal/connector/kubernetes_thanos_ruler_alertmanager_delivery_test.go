package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerAlertmanagerDeliveryWithoutRetainingURLs(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: delivery, namespace: monitoring}
spec:
  version: v0.39.0
  queryEndpoints: [http://query.monitoring:9090]
  alertmanagersUrl:
    - https://alertmanager.private.example/api
    - http://alertmanager.monitoring.svc:9093
    - dnssrv+https://_web._tcp.alertmanager.monitoring.svc
    - https://alertmanager.private.example/api
    - ftp://invalid.private.example
    - ""
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	metadata := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/delivery"].Metadata
	expected := map[string]string{"thanos_ruler_alertmanager_url_count": "3", "thanos_ruler_alertmanager_url_invalid_count": "2", "thanos_ruler_alertmanager_url_duplicate_count": "1", "thanos_ruler_plaintext_alertmanager_url_count": "1", "thanos_ruler_alertmanager_delivery_configured": "true"}
	for key, value := range expected {
		if metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, metadata)
		}
	}
	for key, value := range metadata {
		for _, private := range []string{"alertmanager.private.example", "alertmanager.monitoring.svc", "invalid.private.example"} {
			if strings.Contains(key+value, private) {
				t.Fatalf("Alertmanager URL detail persisted in %s=%q", key, value)
			}
		}
	}
}

func TestKubernetesManifestConnectorMapsThanosRulerAlertmanagerConfigVersion(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: old-config, namespace: monitoring}
spec:
  version: v0.9.0
  queryEndpoints: [http://query.monitoring:9090]
  alertmanagersConfig: {name: alerting-private, key: config-private.yaml}
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: current-config, namespace: monitoring}
spec:
  version: v0.10.0
  queryEndpoints: [http://query.monitoring:9090]
  alertmanagersConfig: {name: alerting-current, key: config-current.yaml}
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: unknown-config, namespace: monitoring}
spec:
  version: custom
  queryEndpoints: [http://query.monitoring:9090]
  alertmanagersConfig: {name: alerting-unknown, key: config-unknown.yaml}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	old := resources["monitoring/old-config"].Metadata
	if old["thanos_ruler_alertmanager_config_valid"] != "true" || old["thanos_ruler_alertmanager_config_version_unsupported"] != "true" || old["thanos_ruler_alertmanager_delivery_configured"] != "true" {
		t.Fatalf("unexpected old config metadata: %#v", old)
	}
	current := resources["monitoring/current-config"].Metadata
	if current["thanos_ruler_alertmanager_config_version_evaluable"] != "true" || current["thanos_ruler_alertmanager_config_version_unsupported"] != "false" {
		t.Fatalf("unexpected current config metadata: %#v", current)
	}
	unknown := resources["monitoring/unknown-config"].Metadata
	if unknown["thanos_ruler_alertmanager_config_version_evaluable"] != "false" || unknown["thanos_ruler_alertmanager_config_version_unsupported"] != "false" {
		t.Fatalf("unexpected unknown config metadata: %#v", unknown)
	}
}

func TestSafeThanosRulerAlertmanagerURLMetadata(t *testing.T) {
	tests := []struct {
		value    string
		scheme   string
		loopback bool
		valid    bool
	}{
		{"https://alertmanager.example/api", "https", false, true},
		{"dnssrv+http://_web._tcp.alertmanager.monitoring.svc", "http", false, true},
		{"http://localhost:9093", "http", true, true},
		{"http://127.0.0.1:9093", "http", true, true},
		{"ftp://alertmanager.example", "", false, false},
		{"https://user:private@alertmanager.example", "", false, false},
		{"alertmanager.example", "", false, false},
	}
	for _, test := range tests {
		scheme, loopback, valid := safeThanosRulerAlertmanagerURLMetadata(test.value)
		if scheme != test.scheme || loopback != test.loopback || valid != test.valid {
			t.Fatalf("unexpected URL metadata for %q: scheme=%q loopback=%t valid=%t", test.value, scheme, loopback, valid)
		}
	}
}
