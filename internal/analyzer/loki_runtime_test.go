package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestLokiNotReadyAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		lokiRuntimeTestResource("not-ready", "true", "false"),
		lokiRuntimeTestResource("ready", "true", "true"),
		lokiRuntimeTestResource("unevaluable", "false", "false"),
		lokiRuntimeTestResource("missing", "", ""),
	}
	wrongSource := lokiRuntimeTestResource("wrong-source", "true", "false")
	wrongSource.Source.System = "pyroscope"
	deprecated := lokiRuntimeTestResource("deprecated", "true", "false")
	deprecated.Status = model.ResourceStatusDeprecated
	resources = append(resources, wrongSource, deprecated)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert runtime resource: %v", err)
		}
	}

	findings, err := NewLokiNotReadyAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 ||
		findings[0].Resource.ID != "not-ready" ||
		findings[0].Type != "LokiNotReady" ||
		findings[0].Severity != model.SeverityCritical ||
		findings[0].Category != model.FindingCategoryReliability ||
		findings[0].Metadata["ready"] != "false" ||
		findings[0].Metadata["scope"] != "configured_component" ||
		model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
		t.Fatalf("unexpected Loki runtime findings: %#v", findings)
	}
}

func lokiRuntimeTestResource(id, available, ready string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeInstance,
		Name:   "Loki Runtime",
		Source: model.SourceInfo{System: "loki", Instance: "http://" + id},
		Metadata: map[string]string{
			model.MetadataLokiRuntime:            "true",
			model.MetadataLokiReadinessAvailable: available,
			model.MetadataLokiReady:              ready,
		},
		Status: model.ResourceStatusActive,
	}
}
