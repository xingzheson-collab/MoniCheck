package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesProbeWithoutProberAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	configured := kubernetesProbeResource("probe-configured", "configured", "static", "1", "blackbox:9115")
	missing := kubernetesProbeResource("probe-missing-prober", "missing-prober", "static", "1", "")
	prometheusTarget := model.Resource{ID: "prom-target", UID: "prom-target", Type: model.ResourceTypeTarget, Name: "api:9090", Status: model.ResourceStatusActive, Source: model.SourceInfo{System: "prometheus"}}

	for _, resource := range []model.Resource{configured, missing, prometheusTarget} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewKubernetesProbeWithoutProberAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != missing.ID {
		t.Fatalf("expected missing prober finding, got %#v", findings)
	}
	if findings[0].Severity != model.SeverityCritical || findings[0].Metadata["namespace"] != "prod" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}
