package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusIngestionSemanticsAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	stStorage := prometheusIngestionSemanticsTestResource("st-storage")
	stStorage.Metadata[model.MetadataPrometheusAgentMode] = "true"
	stStorage.Metadata[model.MetadataPrometheusSTStorageEnabled] = "true"
	stSynthesis := prometheusIngestionSemanticsTestResource("st-synthesis")
	stSynthesis.Metadata[model.MetadataPrometheusSTSynthesisEnabled] = "true"
	nativeDelta := prometheusIngestionSemanticsTestResource("native-delta")
	nativeDelta.Metadata[model.MetadataPrometheusOTLPReceiver] = "true"
	nativeDelta.Metadata[model.MetadataPrometheusOTLPNativeDeltaEnabled] = "true"

	nativeWithoutReceiver := prometheusIngestionSemanticsTestResource("native-no-receiver")
	nativeWithoutReceiver.Metadata[model.MetadataPrometheusOTLPReceiver] = "false"
	nativeWithoutReceiver.Metadata[model.MetadataPrometheusOTLPNativeDeltaEnabled] = "true"
	flagsUnavailable := prometheusIngestionSemanticsTestResource("flags-unavailable")
	flagsUnavailable.Metadata[model.MetadataPrometheusFlagsAvailable] = "false"
	flagsUnavailable.Metadata[model.MetadataPrometheusSTStorageEnabled] = "true"
	wrongSource := prometheusIngestionSemanticsTestResource("wrong-source")
	wrongSource.Source.System = "mimir"
	wrongSource.Metadata[model.MetadataPrometheusSTSynthesisEnabled] = "true"
	inactive := prometheusIngestionSemanticsTestResource("inactive")
	inactive.Status = model.ResourceStatusDeprecated
	inactive.Metadata[model.MetadataPrometheusSTSynthesisEnabled] = "true"
	missing := prometheusIngestionSemanticsTestResource("missing")

	for _, resource := range []model.Resource{
		stStorage, stSynthesis, nativeDelta, nativeWithoutReceiver,
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
		{NewPrometheusExperimentalSTStorageAnalyzer(), "st-storage", "PrometheusExperimentalSTStorage", model.SeverityCritical, model.FindingCategoryLifecycle},
		{NewPrometheusSTSynthesisAnalyzer(), "st-synthesis", "PrometheusSTSynthesisEnabled", model.SeverityWarning, model.FindingCategoryReliability},
		{NewPrometheusOTLPNativeDeltaAnalyzer(), "native-delta", "PrometheusOTLPNativeDeltaIngestion", model.SeverityWarning, model.FindingCategoryReliability},
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

func prometheusIngestionSemanticsTestResource(id string) model.Resource {
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
