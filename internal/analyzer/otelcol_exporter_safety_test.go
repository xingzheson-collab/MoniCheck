package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelExporterSafetyAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	pipeline := otelResource(model.ResourceTypePipeline, "traces", "pipeline:traces")
	unsafe := otelExporterSafetyTestResource("otlphttp/unsafe", map[string]string{
		model.MetadataOTelExporterSendingQueueEnabled:   "false",
		model.MetadataOTelExporterRetryOnFailureEnabled: "false",
		model.MetadataOTelExporterTLSInsecure:           "true",
		model.MetadataOTelExporterTLSInsecureSkipVerify: "true",
	})
	safe := otelExporterSafetyTestResource("otlphttp/safe", map[string]string{
		model.MetadataOTelExporterSendingQueueEnabled:   "true",
		model.MetadataOTelExporterRetryOnFailureEnabled: "true",
		model.MetadataOTelExporterTLSInsecure:           "false",
		model.MetadataOTelExporterTLSInsecureSkipVerify: "false",
	})
	missing := otelExporterSafetyTestResource("otlphttp/missing", map[string]string{})
	unused := otelExporterSafetyTestResource("otlphttp/unused", map[string]string{
		model.MetadataOTelExporterSendingQueueEnabled:   "false",
		model.MetadataOTelExporterRetryOnFailureEnabled: "false",
		model.MetadataOTelExporterTLSInsecure:           "true",
	})
	wrongSource := otelExporterSafetyTestResource("otlphttp/wrong-source", map[string]string{
		model.MetadataOTelExporterSendingQueueEnabled: "false",
		model.MetadataOTelExporterTLSInsecure:         "true",
	})
	wrongSource.Source.System = "plugin"
	inactive := otelExporterSafetyTestResource("otlphttp/inactive", map[string]string{
		model.MetadataOTelExporterRetryOnFailureEnabled: "false",
		model.MetadataOTelExporterTLSInsecureSkipVerify: "true",
	})
	inactive.Status = model.ResourceStatusDeprecated
	for _, resource := range []model.Resource{pipeline, unsafe, safe, missing, unused, wrongSource, inactive} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, exporter := range []model.Resource{unsafe, safe, missing, wrongSource, inactive} {
		if err := store.Relationships.Upsert(ctx, model.Relationship{
			ID:     "pipeline-uses-" + exporter.ID,
			FromID: pipeline.ID,
			ToID:   exporter.ID,
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
		findingType  string
		severity     model.Severity
		category     model.FindingCategory
		evidencePart string
	}{
		{NewOTelExporterSendingQueueDisabledAnalyzer(), "OTelExporterSendingQueueDisabled", model.SeverityWarning, model.FindingCategoryReliability, "sending queue"},
		{NewOTelExporterRetryDisabledAnalyzer(), "OTelExporterRetryDisabled", model.SeverityWarning, model.FindingCategoryReliability, "retry_on_failure"},
		{NewOTelExporterInsecureTLSAnalyzer(), "OTelExporterInsecureTLS", model.SeverityCritical, model.FindingCategorySecurity, "certificate verification"},
	}
	for _, test := range tests {
		t.Run(test.analyzer.ID(), func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
			if err != nil {
				t.Fatalf("execute analyzer: %v", err)
			}
			if len(findings) != 1 ||
				findings[0].Resource.ID != unsafe.ID ||
				findings[0].Type != test.findingType ||
				findings[0].Severity != test.severity ||
				findings[0].Category != test.category ||
				!strings.Contains(findings[0].Evidence[0], test.evidencePart) ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != test.category {
				t.Fatalf("unexpected exporter safety findings: %#v", findings)
			}
		})
	}
}

func otelExporterSafetyTestResource(name string, metadata map[string]string) model.Resource {
	resource := otelResource(model.ResourceTypeExporter, name, "exporter:"+name)
	resource.Metadata[model.MetadataComponentKind] = "exporter"
	resource.Metadata[model.MetadataComponentType] = "otlphttp"
	for key, value := range metadata {
		resource.Metadata[key] = value
	}
	return resource
}
