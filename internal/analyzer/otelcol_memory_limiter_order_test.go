package analyzer

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelMemoryLimiterNotFirstAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	notFirst := otelPipelineResource("logs", "otlp", "batch,memory_limiter/main,attributes", "otlphttp")
	firstWithSuffix := otelPipelineResource("metrics", "otlp", "memory_limiter/metrics,batch", "prometheusremotewrite")
	missing := otelPipelineResource("traces", "otlp", "batch", "otlphttp")
	only := otelPipelineResource("profiles", "otlp", "memory_limiter", "otlphttp")
	inactive := otelPipelineResource("inactive", "otlp", "batch,memory_limiter", "debug")
	inactive.Status = model.ResourceStatusDeprecated
	wrongSource := otelPipelineResource("other", "otlp", "batch,memory_limiter", "debug")
	wrongSource.Source.System = "plugin"

	for _, resource := range []model.Resource{notFirst, firstWithSuffix, missing, only, inactive, wrongSource} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewOTelMemoryLimiterNotFirstAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 ||
		findings[0].Resource.ID != notFirst.ID ||
		findings[0].Type != "OTelMemoryLimiterNotFirst" ||
		findings[0].Severity != model.SeverityWarning ||
		findings[0].Category != model.FindingCategoryReliability ||
		!strings.Contains(findings[0].Evidence[0], "after another processor") ||
		model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
		t.Fatalf("unexpected memory limiter order findings: %#v", findings)
	}
	if _, exists := findings[0].Metadata["processors"]; exists {
		t.Fatalf("finding must not retain the processor list: %#v", findings[0].Metadata)
	}
}
