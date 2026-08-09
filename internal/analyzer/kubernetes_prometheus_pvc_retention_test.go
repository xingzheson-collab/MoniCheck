package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusPVCRetentionAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := prometheusPVCRetentionResource("invalid", "PrometheusAgent")
	invalid.Metadata["prometheus_pvc_retention_applicable"] = "false"
	invalid.Metadata["prometheus_pvc_retention_invalid_setting_count"] = "1"
	deleteSet := prometheusPVCRetentionResource("delete-set", "Prometheus")
	deleteSet.Metadata["prometheus_pvc_when_deleted"] = "Delete"
	deleteScaled := prometheusPVCRetentionResource("delete-scaled", "PrometheusAgent")
	deleteScaled.Metadata["prometheus_pvc_when_scaled"] = "Delete"
	inert := prometheusPVCRetentionResource("inert", "Prometheus")
	inert.Metadata["prometheus_storage_mode"] = "empty-dir"
	inert.Metadata["prometheus_pvc_when_deleted"] = "Delete"
	for _, resource := range []model.Resource{invalid, deleteSet, deleteScaled, inert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidPrometheusPVCRetentionAnalyzer(), invalid.ID},
		{NewKubernetesPrometheusPVCDeleteWithStatefulSetAnalyzer(), deleteSet.ID},
		{NewKubernetesPrometheusPVCDeleteOnScaleDownAnalyzer(), deleteScaled.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func prometheusPVCRetentionResource(name, kind string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "prometheus_storage_mode": "pvc", "prometheus_pvc_retention_applicable": "true", "prometheus_pvc_retention_policy_declared": "true", "prometheus_pvc_retention_invalid_setting_count": "0", "prometheus_pvc_when_deleted": "Retain", "prometheus_pvc_when_scaled": "Retain"}}
}
