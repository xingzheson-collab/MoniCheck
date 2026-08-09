package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerResources(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: bounded, namespace: monitoring}
spec:
  resources:
    requests: {cpu: 750m, memory: 1536Mi}
    limits: {cpu: "2", memory: 3Gi}
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid, namespace: monitoring}
spec:
  resources:
    requests: {cpu: nope, memory: 2Gi}
    limits: {cpu: 500m, memory: 1Gi}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	bounded := resources["monitoring/bounded"]
	for _, key := range []string{"thanos_ruler_cpu_request_positive", "thanos_ruler_memory_request_positive", "thanos_ruler_cpu_limit_positive", "thanos_ruler_memory_limit_positive"} {
		if bounded.Metadata[key] != "true" {
			t.Fatalf("expected %s=true, got %#v", key, bounded.Metadata)
		}
	}
	if bounded.Metadata["thanos_ruler_resource_metadata"] != "true" || bounded.Metadata["thanos_ruler_resource_invalid_setting_count"] != "0" {
		t.Fatalf("unexpected bounded ThanosRuler resources: %#v", bounded.Metadata)
	}
	invalid := resources["monitoring/invalid"]
	if invalid.Metadata["thanos_ruler_resource_invalid_setting_count"] != "2" {
		t.Fatalf("expected malformed CPU and request-above-limit counts, got %#v", invalid.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for key, value := range resource.Metadata {
			for _, private := range []string{"750m", "1536Mi", "3Gi", "2Gi", "1Gi"} {
				if strings.Contains(value, private) {
					t.Fatalf("ThanosRuler resource quantity persisted in %s=%q: %#v", key, value, resource.Metadata)
				}
			}
		}
	}
}
