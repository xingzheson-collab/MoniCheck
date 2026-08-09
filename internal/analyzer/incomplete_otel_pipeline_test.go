package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestIncompleteOTelPipelineAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	complete := otelPipelineResource("metrics", "otlp", "batch", "prometheusremotewrite")
	missingReceiver := otelPipelineResource("traces", "", "batch", "otlphttp/tempo")
	missingExporter := otelPipelineResource("logs", "otlp", "", "")
	deprecatedMissingExporter := otelPipelineResource("deprecated", "otlp", "", "")
	deprecatedMissingExporter.Status = model.ResourceStatusDeprecated
	otherSystem := model.Resource{
		ID:     "pipeline-other",
		Type:   model.ResourceTypePipeline,
		Name:   "traces",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "plugin", Instance: "local", ExternalID: "pipeline:traces"},
	}
	for _, resource := range []model.Resource{complete, missingReceiver, missingExporter, deprecatedMissingExporter, otherSystem} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewIncompleteOTelPipelineAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %#v", findings)
	}
	if findings[0].Resource.ID != missingExporter.ID || findings[0].Metadata["missing"] != "exporters" {
		t.Fatalf("expected missing exporter finding first, got %#v", findings[0])
	}
	if findings[1].Resource.ID != missingReceiver.ID || findings[1].Metadata["missing"] != "receivers" {
		t.Fatalf("expected missing receiver finding second, got %#v", findings[1])
	}
}

func otelPipelineResource(name string, receivers string, processors string, exporters string) model.Resource {
	return model.Resource{
		ID:     "otel-pipeline-" + name,
		Type:   model.ResourceTypePipeline,
		Name:   name,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "otelcol", Instance: "/etc/otelcol.yaml", ExternalID: "pipeline:" + name},
		Metadata: map[string]string{
			model.MetadataComponentKind:      "pipeline",
			model.MetadataPipelineSignal:     pipelineSignalForTest(name),
			model.MetadataPipelineReceivers:  receivers,
			model.MetadataPipelineProcessors: processors,
			model.MetadataPipelineExporters:  exporters,
		},
	}
}

func pipelineSignalForTest(name string) string {
	if name == "metrics" || name == "traces" || name == "logs" {
		return name
	}
	return "unknown"
}
