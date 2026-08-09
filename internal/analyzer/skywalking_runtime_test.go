package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestSkyWalkingOAPUnhealthyAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		skyWalkingRuntimeTestResource("unhealthy", "true", "false"),
		skyWalkingRuntimeTestResource("healthy", "true", "true"),
		skyWalkingRuntimeTestResource("unevaluable", "false", "false"),
		skyWalkingRuntimeTestResource("missing", "", ""),
	}
	wrongSource := skyWalkingRuntimeTestResource("wrong-source", "true", "false")
	wrongSource.Source.System = "pyroscope"
	deprecated := skyWalkingRuntimeTestResource("deprecated", "true", "false")
	deprecated.Status = model.ResourceStatusDeprecated
	resources = append(resources, wrongSource, deprecated)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert runtime resource: %v", err)
		}
	}

	findings, err := NewSkyWalkingOAPUnhealthyAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 ||
		findings[0].Resource.ID != "unhealthy" ||
		findings[0].Type != "SkyWalkingOAPUnhealthy" ||
		findings[0].Severity != model.SeverityCritical ||
		findings[0].Category != model.FindingCategoryReliability ||
		findings[0].Metadata["healthy"] != "false" ||
		model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
		t.Fatalf("unexpected SkyWalking runtime findings: %#v", findings)
	}
}

func skyWalkingRuntimeTestResource(id, available, healthy string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeInstance,
		Name:   "SkyWalking OAP Runtime",
		Source: model.SourceInfo{System: "skywalking", Instance: "http://" + id},
		Metadata: map[string]string{
			model.MetadataSkyWalkingRuntime:         "true",
			model.MetadataSkyWalkingHealthAvailable: available,
			model.MetadataSkyWalkingHealthy:         healthy,
		},
		Status: model.ResourceStatusActive,
	}
}

func TestSkyWalkingOAPUnhealthyAnalyzerUsesGraphQLScoreEvidence(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := skyWalkingRuntimeTestResource("graphql-unhealthy", "true", "false")
	resource.Metadata[model.MetadataSkyWalkingHealthSource] = "graphql"
	resource.Metadata[model.MetadataSkyWalkingHealthScore] = "3"
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert runtime resource: %v", err)
	}

	findings, err := NewSkyWalkingOAPUnhealthyAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 ||
		len(findings[0].Evidence) != 1 ||
		findings[0].Metadata["health_source"] != "graphql" ||
		findings[0].Metadata["health_score"] != "3" ||
		!strings.Contains(findings[0].Evidence[0], "score 3") {
		t.Fatalf("unexpected GraphQL health finding: %#v", findings)
	}
}
