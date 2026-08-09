package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerPresentationWithoutRetainingValues(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: presentation, namespace: monitoring}
spec:
  queryEndpoints: [http://query.monitoring:9090]
  portName: ruler-web
  externalPrefix: https://monitoring.private.example/ruler
  routePrefix: /ruler
  alertQueryUrl: https://query.private.example/thanos
  labels:
    cluster: production-private
    tenant: tenant-private
    thanos_ruler_replica: manual-private
  alertDropLabels: [tenant, tenant, bad-name]
  hostUsers: false
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/presentation"]
	expected := map[string]string{
		"thanos_ruler_port_name_valid":                    "true",
		"thanos_ruler_external_prefix_valid":              "true",
		"thanos_ruler_route_prefix_valid":                 "true",
		"thanos_ruler_alert_query_url_valid":              "true",
		"thanos_ruler_alert_query_url_scheme":             "https",
		"thanos_ruler_external_label_count":               "3",
		"thanos_ruler_replica_label_override":             "true",
		"thanos_ruler_alert_drop_label_count":             "1",
		"thanos_ruler_alert_drop_label_invalid_count":     "1",
		"thanos_ruler_alert_drop_label_duplicate_count":   "1",
		"thanos_ruler_dropped_external_label_count":       "1",
		"thanos_ruler_user_namespace_isolation_enabled":   "true",
		"thanos_ruler_presentation_invalid_setting_count": "2",
	}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
	for key, value := range resource.Metadata {
		for _, private := range []string{"monitoring.private.example", "query.private.example", "production-private", "tenant-private", "manual-private", "cluster", "tenant"} {
			if strings.Contains(key+value, private) {
				t.Fatalf("presentation detail persisted in %s=%q", key, value)
			}
		}
	}
}

func TestKubernetesManifestConnectorRejectsInvalidThanosRulerPresentation(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid-presentation, namespace: monitoring}
spec:
  queryEndpoints: [http://query.monitoring:9090]
  portName: "1234"
  externalPrefix: relative
  routePrefix: https://example.invalid/ruler
  alertQueryUrl: ftp://query.example/ruler
  labels: [invalid]
  alertDropLabels: {invalid: true}
  hostUsers: {enabled: false}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	metadata := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid-presentation"].Metadata
	if metadata["thanos_ruler_presentation_invalid_setting_count"] != "7" || metadata["thanos_ruler_alert_query_url_valid"] != "false" || metadata["thanos_ruler_host_users_valid"] != "false" {
		t.Fatalf("unexpected invalid presentation metadata: %#v", metadata)
	}
}

func TestValidThanosRulerWebPrefix(t *testing.T) {
	tests := []struct {
		value    string
		external bool
		valid    bool
	}{
		{"", false, true},
		{"/ruler", false, true},
		{"https://monitoring.example/ruler", true, true},
		{"https://monitoring.example/ruler", false, false},
		{"relative", true, false},
		{"//monitoring.example/ruler", true, false},
		{"/ruler?token=private", true, false},
	}
	for _, test := range tests {
		if actual := validThanosRulerWebPrefix(test.value, test.external); actual != test.valid {
			t.Fatalf("unexpected prefix validity for %q external=%t: %t", test.value, test.external, actual)
		}
	}
}
