package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPyroscopeNotReadyAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		pyroscopeRuntimeTestResource("not-ready", "true", "false"),
		pyroscopeRuntimeTestResource("ready", "true", "true"),
		pyroscopeRuntimeTestResource("unevaluable", "false", "false"),
		pyroscopeRuntimeTestResource("missing", "", ""),
	}
	wrongSource := pyroscopeRuntimeTestResource("wrong-source", "true", "false")
	wrongSource.Source.System = "grafana"
	deprecated := pyroscopeRuntimeTestResource("deprecated", "true", "false")
	deprecated.Status = model.ResourceStatusDeprecated
	resources = append(resources, wrongSource, deprecated)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert runtime resource: %v", err)
		}
	}

	findings, err := NewPyroscopeNotReadyAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 ||
		findings[0].Resource.ID != "not-ready" ||
		findings[0].Type != "PyroscopeNotReady" ||
		findings[0].Severity != model.SeverityCritical ||
		findings[0].Category != model.FindingCategoryReliability ||
		findings[0].Metadata["ready"] != "false" ||
		model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
		t.Fatalf("unexpected Pyroscope runtime findings: %#v", findings)
	}
}

func pyroscopeRuntimeTestResource(id, available, ready string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeInstance,
		Name:   "Pyroscope Runtime",
		Source: model.SourceInfo{System: "pyroscope", Instance: "http://" + id},
		Metadata: map[string]string{
			model.MetadataPyroscopeRuntime:            "true",
			model.MetadataPyroscopeReadinessAvailable: available,
			model.MetadataPyroscopeReady:              ready,
		},
		Status: model.ResourceStatusActive,
	}
}
