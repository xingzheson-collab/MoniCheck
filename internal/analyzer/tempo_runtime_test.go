package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestTempoNotReadyAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	notReady := tempoRuntimeResource("not-ready", "true", "false")
	ready := tempoRuntimeResource("ready", "true", "true")
	unevaluable := tempoRuntimeResource("unevaluable", "false", "false")
	deprecated := tempoRuntimeResource("deprecated", "true", "false")
	deprecated.Status = model.ResourceStatusDeprecated
	otherSystem := tempoRuntimeResource("other-system", "true", "false")
	otherSystem.Source.System = "other"
	notRuntime := tempoRuntimeResource("not-runtime", "true", "false")
	delete(notRuntime.Metadata, model.MetadataTempoRuntime)
	for _, resource := range []model.Resource{notReady, ready, unevaluable, deprecated, otherSystem, notRuntime} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewTempoNotReadyAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one Tempo not-ready finding, got %#v", findings)
	}
	finding := findings[0]
	if finding.Resource.ID != notReady.ID ||
		finding.Type != "TempoNotReady" ||
		finding.Severity != model.SeverityCritical ||
		finding.Category != model.FindingCategoryReliability {
		t.Fatalf("unexpected Tempo not-ready finding: %#v", finding)
	}
}

func tempoRuntimeResource(id, available, ready string) model.Resource {
	return model.Resource{
		ID:     id,
		Type:   model.ResourceTypeInstance,
		Name:   "Tempo Runtime",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "tempo", Instance: "test"},
		Metadata: map[string]string{
			model.MetadataTempoRuntime:            "true",
			model.MetadataTempoReadinessAvailable: available,
			model.MetadataTempoReady:              ready,
		},
	}
}
