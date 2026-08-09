package connector

import (
	"strings"
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerWorkloadIdentity(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: default-a, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
  serviceAccountName: ruler-runtime
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: default-b, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: isolated, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
  serviceName: ruler-isolated
  serviceAccountName: default
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	if resources["monitoring/default-a"].Metadata["thanos_ruler_shared_service_count"] != "1" || resources["monitoring/default-b"].Metadata["thanos_ruler_shared_service_count"] != "1" {
		t.Fatalf("expected default governing Service to be shared: %#v %#v", resources["monitoring/default-a"].Metadata, resources["monitoring/default-b"].Metadata)
	}
	isolated := resources["monitoring/isolated"]
	if isolated.Metadata["thanos_ruler_service_name_valid"] != "true" || isolated.Metadata["thanos_ruler_shared_service_count"] != "0" || isolated.Metadata["thanos_ruler_custom_service_account"] != "false" || resources["monitoring/default-a"].Metadata["thanos_ruler_custom_service_account"] != "true" {
		t.Fatalf("unexpected workload identity metadata: %#v", isolated.Metadata)
	}
	for _, resource := range resources {
		for key, value := range resource.Metadata {
			if strings.Contains(value, "ruler-runtime") || strings.Contains(value, "ruler-isolated") {
				t.Fatalf("workload identity persisted in %s=%q", key, value)
			}
		}
	}
}

func TestKubernetesManifestConnectorRejectsMalformedThanosRulerWorkloadIdentity(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid, namespace: monitoring}
spec:
  queryEndpoints: [http://thanos-query.monitoring:9090]
  serviceName: "Invalid Service"
  serviceAccountName: []
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/invalid"]
	if resource.Metadata["thanos_ruler_service_name_valid"] != "false" || resource.Metadata["thanos_ruler_service_account_name_valid"] != "false" {
		t.Fatalf("unexpected workload identity metadata: %#v", resource.Metadata)
	}
}
