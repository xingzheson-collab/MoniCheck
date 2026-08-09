package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestGrafanaDatabaseUnhealthyAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		grafanaRuntimeTestResource("unhealthy", "failing"),
		grafanaRuntimeTestResource("healthy", "ok"),
		grafanaRuntimeTestResource("missing", ""),
	}
	wrongSource := grafanaRuntimeTestResource("wrong-source", "failing")
	wrongSource.Source.System = "kubernetes"
	deprecated := grafanaRuntimeTestResource("deprecated", "failing")
	deprecated.Status = model.ResourceStatusDeprecated
	resources = append(resources, wrongSource, deprecated)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert runtime resource: %v", err)
		}
	}

	findings, err := NewGrafanaDatabaseUnhealthyAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 ||
		findings[0].Resource.ID != "unhealthy" ||
		findings[0].Type != "GrafanaDatabaseUnhealthy" ||
		findings[0].Severity != model.SeverityCritical ||
		findings[0].Category != model.FindingCategoryReliability ||
		findings[0].Metadata["database_status"] != "failing" ||
		model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
		t.Fatalf("unexpected Grafana runtime findings: %#v", findings)
	}
}

func grafanaRuntimeTestResource(id string, databaseStatus string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeInstance,
		Name:   "Grafana Runtime",
		Source: model.SourceInfo{System: "grafana", Instance: "http://" + id},
		Metadata: map[string]string{
			model.MetadataGrafanaRuntime:        "true",
			model.MetadataGrafanaDatabaseStatus: databaseStatus,
		},
		Status: model.ResourceStatusActive,
	}
}
