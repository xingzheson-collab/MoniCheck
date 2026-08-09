package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerTerminationGrace(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: graceful, namespace: monitoring}
spec: {terminationGracePeriodSeconds: 120}
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: immediate, namespace: monitoring}
spec: {terminationGracePeriodSeconds: 0}
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid, namespace: monitoring}
spec: {terminationGracePeriodSeconds: -1}
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	if resources["monitoring/graceful"].Metadata["thanos_ruler_termination_grace_seconds"] != "120" || resources["monitoring/graceful"].Metadata["thanos_ruler_termination_grace_valid"] != "true" {
		t.Fatalf("unexpected graceful metadata: %#v", resources["monitoring/graceful"].Metadata)
	}
	if resources["monitoring/immediate"].Metadata["thanos_ruler_termination_grace_seconds"] != "0" || resources["monitoring/immediate"].Metadata["thanos_ruler_termination_grace_valid"] != "true" {
		t.Fatalf("unexpected immediate metadata: %#v", resources["monitoring/immediate"].Metadata)
	}
	if resources["monitoring/invalid"].Metadata["thanos_ruler_termination_grace_valid"] != "false" {
		t.Fatalf("unexpected invalid metadata: %#v", resources["monitoring/invalid"].Metadata)
	}
}
