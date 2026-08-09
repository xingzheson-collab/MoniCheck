package connector

import (
	"testing"
	"time"
)

func TestKubernetesManifestConnectorMapsThanosRulerEvaluationConfiguration(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: evaluation, namespace: monitoring}
spec:
  version: v0.38.0
  queryEndpoints: [http://thanos-query.monitoring:9090]
  evaluationInterval: 30s
  resendDelay: 1m
  ruleOutageTolerance: 1h
  ruleQueryOffset: 2m
  ruleConcurrentEval: 4
  ruleGracePeriod: 10m
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resource := alertmanagerConfigSourceResourcesByName(snapshot.Resources)["monitoring/evaluation"]
	expected := map[string]string{"thanos_ruler_evaluation_interval_seconds": "30", "thanos_ruler_resend_delay_seconds": "60", "thanos_ruler_rule_outage_tolerance_seconds": "3600", "thanos_ruler_rule_query_offset_seconds": "120", "thanos_ruler_rule_grace_period_seconds": "600", "thanos_ruler_rule_concurrent_eval": "4", "thanos_ruler_evaluation_invalid_setting_count": "0", "thanos_ruler_evaluation_unsupported_setting_count": "0", "thanos_ruler_restoration_timing_inconsistent": "false"}
	for key, value := range expected {
		if resource.Metadata[key] != value {
			t.Fatalf("expected %s=%s, got %#v", key, value, resource.Metadata)
		}
	}
}

func TestKubernetesManifestConnectorRejectsInvalidAndUnsupportedThanosRulerEvaluation(t *testing.T) {
	manifest := `
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: invalid-evaluation, namespace: monitoring}
spec:
  version: v0.29.0
  queryEndpoints: [http://thanos-query.monitoring:9090]
  evaluationInterval: invalid
  resendDelay: 0s
  ruleOutageTolerance: 5m
  ruleQueryOffset: 1m
  ruleConcurrentEval: 0
  ruleGracePeriod: 10m
---
apiVersion: monitoring.coreos.com/v1
kind: ThanosRuler
metadata: {name: unknown-version, namespace: monitoring}
spec:
  version: custom
  queryEndpoints: [http://thanos-query.monitoring:9090]
  ruleOutageTolerance: 1h
`
	snapshot, err := kubernetesSnapshotFromManifest(manifest, "test", time.Now().UTC())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	resources := alertmanagerConfigSourceResourcesByName(snapshot.Resources)
	invalid := resources["monitoring/invalid-evaluation"]
	if invalid.Metadata["thanos_ruler_evaluation_invalid_setting_count"] != "3" || invalid.Metadata["thanos_ruler_evaluation_unsupported_setting_count"] != "4" || invalid.Metadata["thanos_ruler_restoration_timing_inconsistent"] != "true" {
		t.Fatalf("unexpected invalid evaluation metadata: %#v", invalid.Metadata)
	}
	unknown := resources["monitoring/unknown-version"]
	if unknown.Metadata["thanos_ruler_evaluation_version_evaluable"] != "false" || unknown.Metadata["thanos_ruler_evaluation_unsupported_setting_count"] != "0" {
		t.Fatalf("unexpected unknown-version metadata: %#v", unknown.Metadata)
	}
}
