package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesMonitorMissingRuntimeTargetAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	covered := kubernetesRuntimeTargetResource("covered", "true", "2", "1")
	missing := kubernetesRuntimeTargetResource("missing", "true", "0", "1")
	unknown := kubernetesRuntimeTargetResource("unknown", "false", "", "1")
	zeroReplica := kubernetesRuntimeTargetResource("zero-replica", "true", "0", "0")
	for _, resource := range []model.Resource{covered, missing, unknown, zeroReplica} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesMonitorMissingRuntimeTargetAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != missing.ID || findings[0].Severity != model.SeverityCritical || findings[0].Category != model.FindingCategoryReliability {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func kubernetesRuntimeTargetResource(name string, evaluable string, runtimeCount string, nonzeroSelected string) model.Resource {
	return model.Resource{
		ID: name, UID: name, Type: model.ResourceTypeTarget, Name: "prod/" + name, Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "kubernetes"},
		Metadata: map[string]string{
			"kubernetes_kind":                       "ServiceMonitor",
			"namespace":                             "prod",
			"prometheus_nonzero_selected_count":     nonzeroSelected,
			model.MetadataRuntimeCoverageEvaluable:  evaluable,
			model.MetadataRuntimeTargetCount:        runtimeCount,
			model.MetadataRuntimeDroppedTargetCount: "0",
			model.MetadataRuntimeCoverageScope:      "singleton",
		},
	}
}
