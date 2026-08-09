package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusFeatureSafetyAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	created := prometheusFeatureSafetyTestResource("created")
	created.Metadata[model.MetadataPrometheusAgentMode] = "true"
	created.Metadata[model.MetadataPrometheusCreatedTimestampZero] = "true"
	otlpDelta := prometheusFeatureSafetyTestResource("otlp-delta")
	otlpDelta.Metadata[model.MetadataPrometheusOTLPReceiver] = "true"
	otlpDelta.Metadata[model.MetadataPrometheusOTLPDeltaToCumulative] = "true"
	xor2 := prometheusFeatureSafetyTestResource("xor2")
	xor2.Metadata[model.MetadataPrometheusXOR2EncodingEnabled] = "true"

	otlpWithoutReceiver := prometheusFeatureSafetyTestResource("otlp-no-receiver")
	otlpWithoutReceiver.Metadata[model.MetadataPrometheusOTLPReceiver] = "false"
	otlpWithoutReceiver.Metadata[model.MetadataPrometheusOTLPDeltaToCumulative] = "true"
	agentXOR2 := prometheusFeatureSafetyTestResource("agent-xor2")
	agentXOR2.Metadata[model.MetadataPrometheusAgentMode] = "true"
	agentXOR2.Metadata[model.MetadataPrometheusXOR2EncodingEnabled] = "true"
	flagsUnavailable := prometheusFeatureSafetyTestResource("flags-unavailable")
	flagsUnavailable.Metadata[model.MetadataPrometheusFlagsAvailable] = "false"
	flagsUnavailable.Metadata[model.MetadataPrometheusCreatedTimestampZero] = "true"
	wrongSource := prometheusFeatureSafetyTestResource("wrong-source")
	wrongSource.Source.System = "thanos"
	wrongSource.Metadata[model.MetadataPrometheusCreatedTimestampZero] = "true"
	inactive := prometheusFeatureSafetyTestResource("inactive")
	inactive.Status = model.ResourceStatusDeprecated
	inactive.Metadata[model.MetadataPrometheusCreatedTimestampZero] = "true"
	missing := prometheusFeatureSafetyTestResource("missing")

	for _, resource := range []model.Resource{
		created, otlpDelta, xor2, otlpWithoutReceiver, agentXOR2,
		flagsUnavailable, wrongSource, inactive, missing,
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert TSDB resource: %v", err)
		}
	}

	tests := []struct {
		analyzer    Analyzer
		resourceID  string
		findingType string
		severity    model.Severity
		category    model.FindingCategory
	}{
		{NewPrometheusCreatedTimestampZeroAnalyzer(), "created", "PrometheusCreatedTimestampZeroIngestion", model.SeverityWarning, model.FindingCategoryCost},
		{NewPrometheusOTLPDeltaToCumulativeAnalyzer(), "otlp-delta", "PrometheusOTLPDeltaToCumulative", model.SeverityWarning, model.FindingCategoryReliability},
		{NewPrometheusExperimentalXOR2Analyzer(), "xor2", "PrometheusExperimentalXOR2Encoding", model.SeverityCritical, model.FindingCategoryLifecycle},
	}
	for _, test := range tests {
		t.Run(test.analyzer.ID(), func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
			if err != nil {
				t.Fatalf("execute analyzer: %v", err)
			}
			if len(findings) != 1 ||
				findings[0].Resource.ID != test.resourceID ||
				findings[0].Type != test.findingType ||
				findings[0].Severity != test.severity ||
				findings[0].Category != test.category ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != test.category {
				t.Fatalf("unexpected findings: %#v", findings)
			}
		})
	}
}

func prometheusFeatureSafetyTestResource(id string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTSDB,
		Name:   "prometheus runtime",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "test"},
		Metadata: map[string]string{
			model.MetadataPrometheusFlagsAvailable: "true",
			model.MetadataPrometheusAgentMode:      "false",
		},
	}
}
