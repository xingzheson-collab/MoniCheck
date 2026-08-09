package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestMissingOTelProcessorAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	complete := otelPipelineResource("metrics", "otlp", "memory_limiter,batch/metrics", "prometheusremotewrite")
	missingMemoryLimiter := otelPipelineResource("traces", "otlp", "batch", "otlphttp/tempo")
	missingBoth := otelPipelineResource("logs", "otlp", "", "debug")
	deprecatedMissingBoth := otelPipelineResource("deprecated", "otlp", "", "debug")
	deprecatedMissingBoth.Status = model.ResourceStatusDeprecated
	otherSystem := model.Resource{
		ID:     "pipeline-other",
		Type:   model.ResourceTypePipeline,
		Name:   "traces",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "plugin", Instance: "local", ExternalID: "pipeline:traces"},
	}
	for _, resource := range []model.Resource{complete, missingMemoryLimiter, missingBoth, deprecatedMissingBoth, otherSystem} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewMissingOTelProcessorAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %#v", findings)
	}
	if findings[0].Resource.ID != missingBoth.ID || findings[0].Metadata["missing"] != "batch,memory_limiter" {
		t.Fatalf("expected logs pipeline missing both processors, got %#v", findings[0])
	}
	if findings[1].Resource.ID != missingMemoryLimiter.ID || findings[1].Metadata["missing"] != "memory_limiter" {
		t.Fatalf("expected traces pipeline missing memory_limiter, got %#v", findings[1])
	}
}

func TestMissingOTelProcessorAnalyzerCustomRequiredProcessors(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	pipeline := otelPipelineResource("traces", "otlp", "batch", "otlphttp/tempo")
	if err := store.Resources.Upsert(ctx, pipeline); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	findings, err := NewMissingOTelProcessorAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"required_otel_processors": []string{"batch"}},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings with custom required processors, got %#v", findings)
	}
}
