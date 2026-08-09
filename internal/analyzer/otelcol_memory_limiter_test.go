package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelMemoryLimiterAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	pipeline := otelResource(model.ResourceTypePipeline, "traces", "pipeline:traces")
	missing := otelMemoryLimiterTestResource("memory_limiter/missing", "false", "true", "0")
	invalid := otelMemoryLimiterTestResource("memory_limiter/invalid", "true", "true", "2")
	valid := otelMemoryLimiterTestResource("memory_limiter/valid", "true", "true", "0")
	dynamic := otelMemoryLimiterTestResource("memory_limiter/dynamic", "true", "false", "0")
	unused := otelMemoryLimiterTestResource("memory_limiter/unused", "false", "true", "0")
	unmarked := otelResource(model.ResourceTypeProcessor, "batch", "processor:batch")
	wrongSource := otelMemoryLimiterTestResource("memory_limiter/wrong-source", "false", "true", "0")
	wrongSource.Source.System = "plugin"
	inactive := otelMemoryLimiterTestResource("memory_limiter/inactive", "false", "true", "0")
	inactive.Status = model.ResourceStatusDeprecated

	for _, resource := range []model.Resource{pipeline, missing, invalid, valid, dynamic, unused, unmarked, wrongSource, inactive} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, processor := range []model.Resource{missing, invalid, valid, dynamic, unmarked, wrongSource, inactive} {
		if err := store.Relationships.Upsert(ctx, model.Relationship{
			ID:     "pipeline-uses-" + processor.ID,
			FromID: pipeline.ID,
			ToID:   processor.ID,
			Type:   model.RelationshipUses,
		}); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	tests := []struct {
		analyzer     Analyzer
		resourceID   string
		findingType  string
		evidencePart string
	}{
		{NewOTelMemoryLimiterWithoutLimitAnalyzer(), missing.ID, "OTelMemoryLimiterWithoutLimit", "neither limit_mib nor limit_percentage"},
		{NewOTelMemoryLimiterInvalidConfigAnalyzer(), invalid.ID, "OTelMemoryLimiterInvalidConfig", "2 explicit invalid"},
	}
	for _, test := range tests {
		t.Run(test.analyzer.ID(), func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
			if err != nil {
				t.Fatalf("execute analyzer: %v", err)
			}
			if len(findings) != 1 ||
				findings[0].Resource.ID != test.resourceID ||
				findings[0].Type != test.findingType ||
				findings[0].Severity != model.SeverityCritical ||
				findings[0].Category != model.FindingCategoryReliability ||
				!strings.Contains(findings[0].Evidence[0], test.evidencePart) ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
				t.Fatalf("unexpected memory limiter findings: %#v", findings)
			}
		})
	}
}

func otelMemoryLimiterTestResource(name, configured, evaluable, issueCount string) model.Resource {
	resource := otelResource(model.ResourceTypeProcessor, name, "processor:"+name)
	resource.Metadata[model.MetadataComponentKind] = "processor"
	resource.Metadata[model.MetadataComponentType] = "memory_limiter"
	resource.Metadata[model.MetadataOTelMemoryLimiterConfig] = "true"
	resource.Metadata[model.MetadataOTelMemoryLimiterLimitConfigured] = configured
	resource.Metadata[model.MetadataOTelMemoryLimiterLimitEvaluable] = evaluable
	resource.Metadata[model.MetadataOTelMemoryLimiterConfigIssueCount] = issueCount
	return resource
}
