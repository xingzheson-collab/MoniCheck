package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelBatchAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	pipeline := otelResource(model.ResourceTypePipeline, "traces", "pipeline:traces")
	invalid := otelBatchTestResource("batch/invalid", "2", "true", "false")
	passThrough := otelBatchTestResource("batch/pass-through", "0", "true", "true")
	valid := otelBatchTestResource("batch/valid", "0", "true", "false")
	dynamic := otelBatchTestResource("batch/dynamic", "0", "false", "false")
	unused := otelBatchTestResource("batch/unused", "2", "true", "true")
	wrongSource := otelBatchTestResource("batch/wrong-source", "2", "true", "true")
	wrongSource.Source.System = "plugin"
	inactive := otelBatchTestResource("batch/inactive", "2", "true", "true")
	inactive.Status = model.ResourceStatusDeprecated
	unmarked := otelResource(model.ResourceTypeProcessor, "attributes", "processor:attributes")

	for _, resource := range []model.Resource{pipeline, invalid, passThrough, valid, dynamic, unused, wrongSource, inactive, unmarked} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, processor := range []model.Resource{invalid, passThrough, valid, dynamic, wrongSource, inactive, unmarked} {
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
		severity     model.Severity
		evidencePart string
	}{
		{NewOTelBatchInvalidConfigAnalyzer(), invalid.ID, "OTelBatchInvalidConfig", model.SeverityCritical, "2 explicit invalid"},
		{NewOTelBatchPassThroughAnalyzer(), passThrough.ID, "OTelBatchPassThrough", model.SeverityWarning, "flushes immediately"},
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
				findings[0].Severity != test.severity ||
				findings[0].Category != model.FindingCategoryReliability ||
				!strings.Contains(findings[0].Evidence[0], test.evidencePart) ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
				t.Fatalf("unexpected batch findings: %#v", findings)
			}
		})
	}
}

func otelBatchTestResource(name, issueCount, passThroughEvaluable, passThrough string) model.Resource {
	resource := otelResource(model.ResourceTypeProcessor, name, "processor:"+name)
	resource.Metadata[model.MetadataComponentKind] = "processor"
	resource.Metadata[model.MetadataComponentType] = "batch"
	resource.Metadata[model.MetadataOTelBatchConfig] = "true"
	resource.Metadata[model.MetadataOTelBatchConfigIssueCount] = issueCount
	resource.Metadata[model.MetadataOTelBatchPassThroughEvaluable] = passThroughEvaluable
	resource.Metadata[model.MetadataOTelBatchPassThrough] = passThrough
	return resource
}
