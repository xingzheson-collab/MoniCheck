package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerStorageAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	single := kubernetesAlertmanagerStorageResource("single", "default-empty-dir", "0", "1", "false", "false")
	ha := kubernetesAlertmanagerStorageResource("ha", "empty-dir", "1", "3", "true", "true")
	persistent := kubernetesAlertmanagerStorageResource("persistent", "pvc", "1", "1", "true", "true")
	conflict := kubernetesAlertmanagerStorageResource("conflict", "empty-dir", "3", "1", "true", "true")
	invalid := kubernetesAlertmanagerStorageResource("invalid", "pvc", "1", "1", "true", "false")
	deprecated := kubernetesAlertmanagerStorageResource("deprecated", "empty-dir", "1", "1", "true", "true")
	deprecated.Status = model.ResourceStatusDeprecated
	nonKubernetes := kubernetesAlertmanagerStorageResource("external", "empty-dir", "1", "1", "true", "true")
	nonKubernetes.Source.System = "alertmanager"
	for _, resource := range []model.Resource{single, ha, persistent, conflict, invalid, deprecated, nonKubernetes} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	findings, err := NewKubernetesEphemeralAlertmanagerStorageAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 3 {
		t.Fatalf("unexpected ephemeral findings: %#v err=%v", findings, err)
	}
	severities := map[string]model.Severity{}
	for _, finding := range findings {
		severities[finding.Resource.ID] = finding.Severity
	}
	if severities[single.ID] != model.SeverityCritical || severities[ha.ID] != model.SeverityWarning || severities[conflict.ID] != model.SeverityCritical {
		t.Fatalf("unexpected ephemeral severities: %#v", severities)
	}

	findings, err = NewKubernetesConflictingAlertmanagerStorageAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != conflict.ID || findings[0].Category != model.FindingCategoryConfiguration {
		t.Fatalf("unexpected conflict findings: %#v err=%v", findings, err)
	}

	findings, err = NewKubernetesInvalidAlertmanagerRetentionAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != invalid.ID || findings[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected retention findings: %#v err=%v", findings, err)
	}
}

func kubernetesAlertmanagerStorageResource(name, mode, optionCount, replicas, retentionDeclared, retentionValid string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeInstance, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_storage_mode": mode, "alertmanager_storage_option_count": optionCount, "alertmanager_replicas": replicas, "alertmanager_retention_declared": retentionDeclared, "alertmanager_retention_valid": retentionValid}}
}
