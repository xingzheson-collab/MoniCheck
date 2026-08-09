package analyzer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelProbabilisticSamplerAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	pipeline := otelResource(model.ResourceTypePipeline, "traces", "pipeline:traces")
	logsPipeline := otelResource(model.ResourceTypePipeline, "logs", "pipeline:logs")
	logsPipeline.Metadata[model.MetadataPipelineSignal] = "logs"
	full := otelProbabilisticSamplerTestResource("probabilistic_sampler/full", "true", "true", "false", "0")
	dropAll := otelProbabilisticSamplerTestResource("probabilistic_sampler/drop-all", "true", "false", "true", "0")
	invalid := otelProbabilisticSamplerTestResource("probabilistic_sampler/invalid", "false", "", "", "1")
	invalidOptions := otelProbabilisticSamplerTestResource("probabilistic_sampler/invalid-options", "true", "false", "false", "0")
	invalidOptions.Metadata[model.MetadataOTelProbabilisticOptionIssueCount] = "2"
	failOpen := otelProbabilisticSamplerTestResource("probabilistic_sampler/fail-open", "true", "false", "false", "0")
	failOpen.Metadata[model.MetadataOTelProbabilisticFailClosed] = "false"
	recordMissing := otelProbabilisticSamplerTestResource("probabilistic_sampler/record-missing", "true", "false", "false", "0")
	recordMissing.Metadata[model.MetadataOTelProbabilisticUsedByLogs] = "true"
	recordMissing.Metadata[model.MetadataOTelProbabilisticAttributeSourceRecord] = "true"
	unsupportedMode := otelProbabilisticSamplerTestResource("probabilistic_sampler/record-unsupported-mode", "true", "false", "false", "0")
	unsupportedMode.Metadata[model.MetadataOTelProbabilisticUsedByLogs] = "true"
	unsupportedMode.Metadata[model.MetadataOTelProbabilisticAttributeSourceRecord] = "true"
	unsupportedMode.Metadata[model.MetadataOTelProbabilisticFromAttributeConfigured] = "true"
	unsupportedMode.Metadata[model.MetadataOTelProbabilisticRecordSourceModeCompatible] = "false"
	tracesRecordMissing := otelProbabilisticSamplerTestResource("probabilistic_sampler/traces-record-missing", "true", "false", "false", "0")
	tracesRecordMissing.Metadata[model.MetadataOTelProbabilisticAttributeSourceRecord] = "true"
	bounded := otelProbabilisticSamplerTestResource("probabilistic_sampler/bounded", "true", "false", "false", "0")
	dynamic := otelProbabilisticSamplerTestResource("probabilistic_sampler/dynamic", "false", "", "", "0")
	unused := otelProbabilisticSamplerTestResource("probabilistic_sampler/unused", "true", "true", "false", "0")
	wrongSource := otelProbabilisticSamplerTestResource("probabilistic_sampler/wrong-source", "true", "true", "false", "0")
	wrongSource.Source.System = "plugin"
	inactive := otelProbabilisticSamplerTestResource("probabilistic_sampler/inactive", "true", "false", "true", "0")
	inactive.Status = model.ResourceStatusDeprecated
	unmarked := otelResource(model.ResourceTypeProcessor, "attributes", "processor:attributes")

	for _, resource := range []model.Resource{pipeline, logsPipeline, full, dropAll, invalid, invalidOptions, failOpen, recordMissing, unsupportedMode, tracesRecordMissing, bounded, dynamic, unused, wrongSource, inactive, unmarked} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, processor := range []model.Resource{full, dropAll, invalid, invalidOptions, failOpen, tracesRecordMissing, bounded, dynamic, wrongSource, inactive, unmarked} {
		if err := store.Relationships.Upsert(ctx, model.Relationship{
			ID:     "pipeline-uses-" + processor.ID,
			FromID: pipeline.ID,
			ToID:   processor.ID,
			Type:   model.RelationshipUses,
		}); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID:     "logs-pipeline-uses-" + recordMissing.ID,
		FromID: logsPipeline.ID,
		ToID:   recordMissing.ID,
		Type:   model.RelationshipUses,
	}); err != nil {
		t.Fatalf("upsert logs relationship: %v", err)
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID:     "logs-pipeline-uses-" + unsupportedMode.ID,
		FromID: logsPipeline.ID,
		ToID:   unsupportedMode.ID,
		Type:   model.RelationshipUses,
	}); err != nil {
		t.Fatalf("upsert unsupported-mode logs relationship: %v", err)
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
		severity     model.Severity
		category     model.FindingCategory
	}{
		{NewOTelProbabilisticSamplerFullCaptureAnalyzer(), full.ID, "OTelProbabilisticSamplerFullCapture", "effective full-capture", model.SeverityWarning, model.FindingCategoryCost},
		{NewOTelProbabilisticSamplerDropAllAnalyzer(), dropAll.ID, "OTelProbabilisticSamplerDropAll", "effective zero", model.SeverityCritical, model.FindingCategoryReliability},
		{NewOTelProbabilisticSamplerInvalidConfigAnalyzer(), invalid.ID, "OTelProbabilisticSamplerInvalidConfig", "1 explicit sampling percentage", model.SeverityCritical, model.FindingCategoryReliability},
		{NewOTelProbabilisticSamplerInvalidOptionsAnalyzer(), invalidOptions.ID, "OTelProbabilisticSamplerInvalidOptions", "2 explicit option", model.SeverityCritical, model.FindingCategoryReliability},
		{NewOTelProbabilisticSamplerFailOpenAnalyzer(), failOpen.ID, "OTelProbabilisticSamplerFailOpen", "pass telemetry", model.SeverityWarning, model.FindingCategoryCost},
		{NewOTelProbabilisticSamplerRecordSourceWithoutAttributeAnalyzer(), recordMissing.ID, "OTelProbabilisticSamplerRecordSourceWithoutAttribute", "no source attribute", model.SeverityCritical, model.FindingCategoryReliability},
		{NewOTelProbabilisticSamplerRecordSourceUnsupportedModeAnalyzer(), unsupportedMode.ID, "OTelProbabilisticSamplerRecordSourceUnsupportedMode", "ignores the record attribute", model.SeverityCritical, model.FindingCategoryReliability},
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
				findings[0].Category != test.category ||
				!strings.Contains(findings[0].Evidence[0], test.evidencePart) ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != test.category {
				t.Fatalf("unexpected probabilistic-sampler findings: %#v", findings)
			}
			encoded, err := json.Marshal(findings[0])
			if err != nil {
				t.Fatalf("marshal finding: %v", err)
			}
			for _, privateValue := range []string{"12.345678", "PRIVATE_SAMPLING_PERCENTAGE", "-765.432"} {
				if strings.Contains(string(encoded), privateValue) {
					t.Fatalf("finding leaked %q: %s", privateValue, encoded)
				}
			}
		})
	}
}

func otelProbabilisticSamplerTestResource(name, evaluable, fullCapture, dropAll, issueCount string) model.Resource {
	resource := otelResource(model.ResourceTypeProcessor, name, "processor:"+name)
	resource.Metadata[model.MetadataComponentKind] = "processor"
	resource.Metadata[model.MetadataComponentType] = "probabilistic_sampler"
	resource.Metadata[model.MetadataOTelProbabilisticSamplerConfig] = "true"
	resource.Metadata[model.MetadataOTelProbabilisticPercentageEvaluable] = evaluable
	if fullCapture != "" {
		resource.Metadata[model.MetadataOTelProbabilisticFullCapture] = fullCapture
	}
	if dropAll != "" {
		resource.Metadata[model.MetadataOTelProbabilisticDropAll] = dropAll
	}
	resource.Metadata[model.MetadataOTelProbabilisticConfigIssueCount] = issueCount
	resource.Metadata[model.MetadataOTelProbabilisticOptionIssueCount] = "0"
	resource.Metadata[model.MetadataOTelProbabilisticFailClosedEvaluable] = "true"
	resource.Metadata[model.MetadataOTelProbabilisticFailClosed] = "true"
	resource.Metadata[model.MetadataOTelProbabilisticUsedByLogs] = "false"
	resource.Metadata[model.MetadataOTelProbabilisticAttributeSourceEvaluable] = "true"
	resource.Metadata[model.MetadataOTelProbabilisticAttributeSourceRecord] = "false"
	resource.Metadata[model.MetadataOTelProbabilisticFromAttributeEvaluable] = "true"
	resource.Metadata[model.MetadataOTelProbabilisticFromAttributeConfigured] = "false"
	resource.Metadata[model.MetadataOTelProbabilisticModeEvaluable] = "true"
	resource.Metadata[model.MetadataOTelProbabilisticRecordSourceModeCompatible] = "true"
	return resource
}
