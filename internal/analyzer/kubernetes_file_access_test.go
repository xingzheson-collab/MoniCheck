package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesMonitorArbitraryFileAccessAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		kubernetesFileAccessMonitor("risky", "ServiceMonitor", "4", "2", "1"),
		kubernetesFileAccessMonitor("protected", "PodMonitor", "1", "1", "0"),
		kubernetesFileAccessMonitor("safe", "Probe", "0", "2", "0"),
		kubernetesFileAccessMonitor("unselected", "ServiceMonitor", "1", "0", "0"),
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesMonitorArbitraryFileAccessAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != "risky" || findings[0].Severity != model.SeverityCritical || findings[0].Category != model.FindingCategorySecurity {
		t.Fatalf("unexpected arbitrary file access findings: %#v err=%v", findings, err)
	}
}

func kubernetesFileAccessMonitor(id, kind, references, selected, unprotected string) model.Resource {
	return model.Resource{ID: id, UID: id, Type: model.ResourceTypeTarget, Name: "monitoring/" + id, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{"kubernetes_kind": kind, "namespace": "monitoring", "monitor_arbitrary_file_reference_count": references, "prometheus_selected_count": selected, "prometheus_arbitrary_file_access_unprotected_count": unprotected}}
}
