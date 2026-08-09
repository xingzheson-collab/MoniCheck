package analyzer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelBatchBeforeSamplingAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	beforeTail := otelPipelineResource("logs", "otlp", "memory_limiter,batch/private,attributes,tail_sampling/private", "otlphttp")
	beforeProbabilistic := otelPipelineResource("metrics", "otlp", "batch,probabilistic_sampler/metrics", "prometheusremotewrite")
	afterTail := otelPipelineResource("traces", "otlp", "memory_limiter,tail_sampling/main,batch", "otlphttp")
	noSampler := otelPipelineResource("profiles", "otlp", "memory_limiter,batch,filter", "otlphttp")
	noBatch := otelPipelineResource("no-batch", "otlp", "tail_sampling", "otlphttp")
	similarNames := otelPipelineResource("similar", "otlp", "batchish,tail_samplingish,batch", "otlphttp")
	inactive := otelPipelineResource("inactive", "otlp", "batch,tail_sampling", "debug")
	inactive.Status = model.ResourceStatusDeprecated
	wrongSource := otelPipelineResource("other", "otlp", "batch,tail_sampling", "debug")
	wrongSource.Source.System = "plugin"

	for _, resource := range []model.Resource{
		beforeTail,
		beforeProbabilistic,
		afterTail,
		noSampler,
		noBatch,
		similarNames,
		inactive,
		wrongSource,
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewOTelBatchBeforeSamplingAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 ||
		findings[0].Resource.ID != beforeTail.ID ||
		findings[1].Resource.ID != beforeProbabilistic.ID {
		t.Fatalf("unexpected batch order findings: %#v", findings)
	}
	for _, finding := range findings {
		if finding.Type != "OTelBatchBeforeSampling" ||
			finding.Severity != model.SeverityWarning ||
			finding.Category != model.FindingCategoryReliability ||
			!strings.Contains(finding.Evidence[0], "batch before a sampling processor") ||
			model.DefaultFindingCategory(finding.Type, finding.Resource.Type) != model.FindingCategoryReliability {
			t.Fatalf("unexpected batch order finding: %#v", finding)
		}
		if len(finding.Metadata) != 2 || finding.Metadata["analyzer_id"] != OTelBatchBeforeSamplingAnalyzerID {
			t.Fatalf("finding must retain only bounded metadata: %#v", finding.Metadata)
		}
		encoded, err := json.Marshal(finding)
		if err != nil {
			t.Fatalf("marshal finding: %v", err)
		}
		for _, privateValue := range []string{"private", "attributes,tail_sampling", "probabilistic_sampler/metrics"} {
			if strings.Contains(string(encoded), privateValue) {
				t.Fatalf("finding leaked %q: %s", privateValue, encoded)
			}
		}
	}
}
