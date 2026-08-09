package analyzer

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesMonitorDroppedRuntimeTargetAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	allDropped := kubernetesDroppedCoverageResource("all", 0, 3)
	highRatio := kubernetesDroppedCoverageResource("high", 4, 6)
	lowRatio := kubernetesDroppedCoverageResource("low", 8, 2)
	smallSample := kubernetesDroppedCoverageResource("small", 1, 1)
	for _, resource := range []model.Resource{allDropped, highRatio, lowRatio, smallSample} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	allFindings, err := NewKubernetesMonitorAllRuntimeTargetsDroppedAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute all-dropped analyzer: %v", err)
	}
	if len(allFindings) != 1 || allFindings[0].Resource.ID != allDropped.ID || allFindings[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected all-dropped findings: %#v", allFindings)
	}
	highFindings, err := NewKubernetesMonitorHighRuntimeTargetDropRatioAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute high-ratio analyzer: %v", err)
	}
	if len(highFindings) != 1 || highFindings[0].Resource.ID != highRatio.ID || highFindings[0].Severity != model.SeverityWarning {
		t.Fatalf("unexpected high-ratio findings: %#v", highFindings)
	}
}

func kubernetesDroppedCoverageResource(name string, active int, dropped int) model.Resource {
	observed := active + dropped
	ratio := 0.0
	if observed > 0 {
		ratio = float64(dropped) / float64(observed)
	}
	return model.Resource{
		ID: name, UID: name, Type: model.ResourceTypeTarget, Name: "prod/" + name, Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "kubernetes"},
		Metadata: map[string]string{
			"kubernetes_kind":                        "ServiceMonitor",
			"namespace":                              "prod",
			model.MetadataRuntimeCoverageEvaluable:   "true",
			model.MetadataRuntimeTargetCount:         strconv.Itoa(active),
			model.MetadataRuntimeDroppedTargetCount:  strconv.Itoa(dropped),
			model.MetadataRuntimeObservedTargetCount: strconv.Itoa(observed),
			model.MetadataRuntimeDroppedTargetRatio:  fmt.Sprintf("%.4f", ratio),
		},
	}
}
