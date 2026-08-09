package connector

import (
	"strings"
	"testing"
	"time"

	"monicheck/internal/model"
)

func TestKubernetesManifestConnectorMapsThanosRulerArgumentsWithoutRetainingValues(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: arguments, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
  additionalArgs:
    - {name: secret-flag, value: private-value}
    - {name: secret-flag, value: replacement-value}
    - {name: another-flag}
    - {value: missing-name}
    - invalid
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/arguments"]
	expected := map[string]string{"thanos_ruler_argument_metadata": "true", "thanos_ruler_additional_args_declared": "true", "thanos_ruler_additional_arg_count": "3", "thanos_ruler_additional_arg_invalid_count": "2", "thanos_ruler_additional_arg_duplicate_count": "1"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
	for key, value := range resource.Metadata {
		for _, secret := range []string{"secret-flag", "private-value", "replacement-value", "another-flag", "missing-name"} {
			if strings.Contains(key, secret) || strings.Contains(value, secret) {
				t.Fatalf("argument detail persisted in %s=%q", key, value)
			}
		}
	}
}

func TestKubernetesManifestConnectorMapsThanosRulerFeaturesAndVersionBoundary(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: old-features, namespace: monitoring}
spec:
  version: v0.38.0
  queryEndpoints: [http://thanos-query.monitoring:9090]
  enableFeatures: [feature-private, feature-private, ""]
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: current-features, namespace: monitoring}
spec:
  version: v0.39.0
  queryEndpoints: [http://thanos-query.monitoring:9090]
  enableFeatures: [feature-current]
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	old := resources["monitoring/old-features"]
	if old.Metadata["thanos_ruler_feature_count"] != "2" || old.Metadata["thanos_ruler_feature_invalid_count"] != "1" || old.Metadata["thanos_ruler_feature_duplicate_count"] != "1" || old.Metadata["thanos_ruler_feature_version_unsupported"] != "true" {
		t.Fatalf("unexpected old feature metadata: %#v", old.Metadata)
	}
	current := resources["monitoring/current-features"]
	if current.Metadata["thanos_ruler_feature_version_evaluable"] != "true" || current.Metadata["thanos_ruler_feature_version_unsupported"] != "false" {
		t.Fatalf("unexpected current feature metadata: %#v", current.Metadata)
	}
	for _, resource := range []model.Resource{old, current} {
		for key, value := range resource.Metadata {
			if strings.Contains(key+value, "feature-private") || strings.Contains(key+value, "feature-current") {
				t.Fatalf("feature identity persisted in %s=%q", key, value)
			}
		}
	}
}
