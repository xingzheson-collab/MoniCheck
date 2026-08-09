package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsPrometheusResources(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: bounded, namespace: monitoring}
spec:
  resources:
    requests: {cpu: 750m, memory: 1536Mi}
    limits: {cpu: "2", memory: 3Gi}
---
apiVersion: monitoring.coreos.com/v1alpha1
kind: PrometheusAgent
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
	for _, key := range []string{"prometheus_cpu_request_positive", "prometheus_memory_request_positive", "prometheus_cpu_limit_positive", "prometheus_memory_limit_positive"} {
		if bounded.Metadata[key] != "true" {
			t.Fatalf("expected %s=true, got %#v", key, bounded.Metadata)
		}
	}
	if bounded.Metadata["prometheus_resource_metadata"] != "true" || bounded.Metadata["prometheus_resource_invalid_setting_count"] != "0" {
		t.Fatalf("unexpected bounded Prometheus resources: %#v", bounded.Metadata)
	}
	invalid := resources["monitoring/invalid"]
	if invalid.Metadata["prometheus_resource_invalid_setting_count"] != "2" {
		t.Fatalf("expected malformed CPU and request-above-limit counts, got %#v", invalid.Metadata)
	}
	for _, resource := range snapshot.Resources {
		for key, value := range resource.Metadata {
			for _, private := range []string{"750m", "1536Mi", "3Gi", "2Gi", "1Gi"} {
				if strings.Contains(value, private) {
					t.Fatalf("Prometheus resource quantity persisted in %s=%q: %#v", key, value, resource.Metadata)
				}
			}
		}
	}
}

func TestKubernetesResourceRequirementsSummarySharedWithAlertmanager(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: Prometheus
metadata: {name: prometheus, namespace: monitoring}
spec:
  resources:
    requests: {cpu: 2, memory: 2Gi}
    limits: {cpu: 1, memory: 1Gi}
---
apiVersion: monitoring.coreos.com/v1
kind: Alertmanager
metadata: {name: alertmanager, namespace: monitoring}
spec:
  resources:
    requests: {cpu: 2, memory: 2Gi}
    limits: {cpu: 1, memory: 1Gi}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	prometheus := resources["monitoring/prometheus"]
	alertmanager := resources["monitoring/alertmanager"]
	for _, suffix := range []string{"resource_invalid_setting_count", "cpu_request_positive", "memory_request_positive", "cpu_limit_positive", "memory_limit_positive"} {
		if prometheus.Metadata["prometheus_"+suffix] != alertmanager.Metadata["alertmanager_"+suffix] {
			t.Fatalf("shared resource parsing diverged for %s: prometheus=%q alertmanager=%q", suffix, prometheus.Metadata["prometheus_"+suffix], alertmanager.Metadata["alertmanager_"+suffix])
		}
	}
}
