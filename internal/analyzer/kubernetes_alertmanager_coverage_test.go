package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesAlertmanagerConfigCoverageAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	selected := kubernetesAlertmanagerConfigResource("selected", "1", "1", "true")
	zeroOnly := kubernetesAlertmanagerConfigResource("zero-only", "1", "0", "true")
	unselected := kubernetesAlertmanagerConfigResource("unselected", "0", "0", "true")
	unknown := kubernetesAlertmanagerConfigResource("unknown", "0", "0", "false")
	for _, resource := range []model.Resource{selected, zeroOnly, unselected, unknown} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}
	findings, err := NewKubernetesAlertmanagerConfigNotSelectedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != unselected.ID {
		t.Fatalf("unexpected unselected findings: %#v err=%v", findings, err)
	}
	findings, err = NewKubernetesAlertmanagerConfigZeroReplicaCoverageAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != zeroOnly.ID || findings[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected zero findings: %#v err=%v", findings, err)
	}
}

func TestKubernetesAlertmanagerPausedAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	paused := model.Resource{ID: "paused", UID: "paused", Type: model.ResourceTypeInstance, Name: "monitoring/main", Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "Alertmanager", "namespace": "monitoring", "alertmanager_paused": "true"}}
	if err := store.Resources.Upsert(ctx, paused); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	findings, err := NewKubernetesAlertmanagerPausedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != paused.ID {
		t.Fatalf("unexpected findings: %#v err=%v", findings, err)
	}
}

func kubernetesAlertmanagerConfigResource(name, selected, nonzero, evaluable string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeNotificationPolicy, Name: name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": "AlertmanagerConfig", "namespace": "prod", "alertmanager_selection_candidate": "true", "alertmanager_selection_evaluable": evaluable, "alertmanager_selected_count": selected, "alertmanager_nonzero_selected_count": nonzero}}
}
