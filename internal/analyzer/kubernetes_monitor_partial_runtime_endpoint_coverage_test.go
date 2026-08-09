package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesMonitorPartialRuntimeEndpointCoverageAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	complete := kubernetesEndpointCoverageResource("complete", "2", "2", "0", "", "3")
	partial := kubernetesEndpointCoverageResource("partial", "3", "2", "1", "2", "4")
	missingMonitor := kubernetesEndpointCoverageResource("missing-monitor", "2", "0", "2", "0,1", "0")
	unknown := kubernetesEndpointCoverageResource("unknown", "2", "", "", "", "")
	unknown.Metadata[model.MetadataRuntimeEndpointEvaluable] = "false"
	for _, resource := range []model.Resource{complete, partial, missingMonitor, unknown} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesMonitorPartialRuntimeEndpointCoverageAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != partial.ID || findings[0].Severity != model.SeverityWarning || findings[0].Metadata["prometheus_runtime_missing_endpoints"] != "2" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func kubernetesEndpointCoverageResource(name string, expected string, covered string, missingCount string, missing string, runtimeTargets string) model.Resource {
	return model.Resource{
		ID: name, UID: name, Type: model.ResourceTypeTarget, Name: "prod/" + name, Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "kubernetes"},
		Metadata: map[string]string{
			"kubernetes_kind":                         "ServiceMonitor",
			"namespace":                               "prod",
			"endpoint_count":                          expected,
			model.MetadataRuntimeTargetCount:          runtimeTargets,
			model.MetadataRuntimeEndpointEvaluable:    "true",
			model.MetadataRuntimeEndpointCount:        covered,
			model.MetadataRuntimeMissingEndpointCount: missingCount,
			model.MetadataRuntimeMissingEndpoints:     missing,
		},
	}
}
