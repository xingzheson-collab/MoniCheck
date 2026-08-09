package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestUnusedOTelComponentAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	pipeline := otelResource(model.ResourceTypePipeline, "traces", "pipeline:traces")
	usedReceiver := otelResource(model.ResourceTypeReceiver, "otlp", "receiver:otlp")
	unusedProcessor := otelResource(model.ResourceTypeProcessor, "transform/unused", "processor:transform/unused")
	unusedExporter := otelResource(model.ResourceTypeExporter, "debug/unused", "exporter:debug/unused")
	usedExtension := otelResource(model.ResourceTypeExtension, "health_check", "extension:health_check")
	unusedExtension := otelResource(model.ResourceTypeExtension, "pprof/unused", "extension:pprof/unused")
	unusedConnector := otelResource(model.ResourceTypeTelemetryConnector, "count/unused", "connector:count/unused")
	collector := otelResource(model.ResourceTypeInstance, "OpenTelemetry Collector", "collector")
	collector.Metadata[model.MetadataOTelCollectorConfigInstance] = "true"
	deprecatedUnusedExporter := otelResource(model.ResourceTypeExporter, "debug/deprecated", "exporter:debug/deprecated")
	deprecatedUnusedExporter.Status = model.ResourceStatusDeprecated
	otherSystemExporter := model.Resource{
		ID:     "exporter-other",
		Type:   model.ResourceTypeExporter,
		Name:   "debug/other",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "exporter:debug/other"},
	}
	for _, resource := range []model.Resource{pipeline, usedReceiver, unusedProcessor, unusedExporter, usedExtension, unusedExtension, unusedConnector, collector, deprecatedUnusedExporter, otherSystemExporter} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID:     "pipeline-uses-receiver",
		FromID: pipeline.ID,
		ToID:   usedReceiver.ID,
		Type:   model.RelationshipUses,
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID:     "collector-uses-extension",
		FromID: collector.ID,
		ToID:   usedExtension.ID,
		Type:   model.RelationshipUses,
	}); err != nil {
		t.Fatalf("upsert extension relationship: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewUnusedOTelComponentAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %#v", findings)
	}
	if findings[0].Resource.ID != unusedExporter.ID ||
		findings[1].Resource.ID != unusedExtension.ID ||
		findings[2].Resource.ID != unusedProcessor.ID ||
		findings[3].Resource.ID != unusedConnector.ID {
		t.Fatalf("expected unused otel exporter, extension, processor, and connector findings, got %#v", findings)
	}
}

func otelResource(resourceType model.ResourceType, name string, externalID string) model.Resource {
	kind := strings.ToLower(string(resourceType))
	switch resourceType {
	case model.ResourceTypeReceiver:
		kind = "receiver"
	case model.ResourceTypeProcessor:
		kind = "processor"
	case model.ResourceTypeExporter:
		kind = "exporter"
	case model.ResourceTypePipeline:
		kind = "pipeline"
	case model.ResourceTypeExtension:
		kind = "extension"
	case model.ResourceTypeTelemetryConnector:
		kind = "connector"
	}
	return model.Resource{
		ID:     "otel-" + externalID,
		Type:   resourceType,
		Name:   name,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "otelcol", Instance: "/etc/otelcol.yaml", ExternalID: externalID},
		Metadata: map[string]string{
			model.MetadataComponentKind: kind,
		},
	}
}
