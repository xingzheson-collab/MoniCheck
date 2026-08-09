package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDebugOTelExporterAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	pipeline := otelResource(model.ResourceTypePipeline, "traces", "pipeline:traces")
	deprecatedPipeline := otelResource(model.ResourceTypePipeline, "deprecated", "pipeline:deprecated")
	deprecatedPipeline.Status = model.ResourceStatusDeprecated
	debugExporter := otelResource(model.ResourceTypeExporter, "debug/trace", "exporter:debug/trace")
	debugExporter.Metadata[model.MetadataComponentType] = "debug"
	deprecatedDebugExporter := otelResource(model.ResourceTypeExporter, "debug/deprecated", "exporter:debug/deprecated")
	deprecatedDebugExporter.Status = model.ResourceStatusDeprecated
	deprecatedDebugExporter.Metadata[model.MetadataComponentType] = "debug"
	legacyDebugExporter := otelResource(model.ResourceTypeExporter, "debug/legacy", "exporter:debug/legacy")
	legacyDebugExporter.Metadata[model.MetadataComponentType] = "debug"
	otlpExporter := otelResource(model.ResourceTypeExporter, "otlphttp/tempo", "exporter:otlphttp/tempo")
	otlpExporter.Metadata[model.MetadataComponentType] = "otlphttp"
	unusedDebugExporter := otelResource(model.ResourceTypeExporter, "logging/unused", "exporter:logging/unused")
	unusedDebugExporter.Metadata[model.MetadataComponentType] = "logging"
	otherSystemExporter := model.Resource{
		ID:     "exporter-other",
		Type:   model.ResourceTypeExporter,
		Name:   "debug/other",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "plugin", Instance: "local", ExternalID: "exporter:debug/other"},
		Metadata: map[string]string{
			model.MetadataComponentType: "debug",
		},
	}
	for _, resource := range []model.Resource{pipeline, deprecatedPipeline, debugExporter, deprecatedDebugExporter, legacyDebugExporter, otlpExporter, unusedDebugExporter, otherSystemExporter} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, relationship := range []model.Relationship{
		{ID: "pipeline-uses-debug", FromID: pipeline.ID, ToID: debugExporter.ID, Type: model.RelationshipUses},
		{ID: "pipeline-uses-deprecated-debug", FromID: pipeline.ID, ToID: deprecatedDebugExporter.ID, Type: model.RelationshipUses},
		{ID: "deprecated-pipeline-uses-debug", FromID: deprecatedPipeline.ID, ToID: legacyDebugExporter.ID, Type: model.RelationshipUses},
		{ID: "pipeline-uses-otlp", FromID: pipeline.ID, ToID: otlpExporter.ID, Type: model.RelationshipUses},
	} {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewDebugOTelExporterAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %#v", findings)
	}
	if findings[0].Resource.ID != debugExporter.ID || findings[0].Metadata["component_type"] != "debug" {
		t.Fatalf("expected debug exporter finding, got %#v", findings[0])
	}
}
