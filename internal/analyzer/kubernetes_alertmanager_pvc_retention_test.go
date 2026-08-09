package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerPVCRetentionAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	retained := alertmanagerPVCRetentionResource("retained")
	invalid := alertmanagerPVCRetentionResource("invalid")
	invalid.Metadata["alertmanager_pvc_retention_invalid_setting_count"] = "2"
	deleteSet := alertmanagerPVCRetentionResource("delete-set")
	deleteSet.Metadata["alertmanager_pvc_when_deleted"] = "Delete"
	deleteScaled := alertmanagerPVCRetentionResource("delete-scaled")
	deleteScaled.Metadata["alertmanager_pvc_when_scaled"] = "Delete"
	inert := alertmanagerPVCRetentionResource("inert")
	inert.Metadata["alertmanager_storage_mode"] = "empty-dir"
	inert.Metadata["alertmanager_pvc_when_deleted"] = "Delete"
	for _, resource := range []model.Resource{retained, invalid, deleteSet, deleteScaled, inert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
	}{
		{NewKubernetesInvalidAlertmanagerPVCRetentionAnalyzer(), invalid.ID},
		{NewKubernetesAlertmanagerPVCDeleteWithStatefulSetAnalyzer(), deleteSet.ID},
		{NewKubernetesAlertmanagerPVCDeleteOnScaleDownAnalyzer(), deleteScaled.ID},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resource {
			t.Fatalf("unexpected %s findings: %#v err=%v", test.analyzer.ID(), findings, err)
		}
	}
}

func alertmanagerPVCRetentionResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_storage_mode": "pvc", "alertmanager_pvc_retention_policy_declared": "true", "alertmanager_pvc_retention_invalid_setting_count": "0", "alertmanager_pvc_when_deleted": "Retain", "alertmanager_pvc_when_scaled": "Retain"}}
}
