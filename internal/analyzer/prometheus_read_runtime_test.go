package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusReadRuntimeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	bounded := prometheusReadRuntimeTestResource("bounded", "10", "50000000", "true", "10000")
	unboundedConcurrency := prometheusReadRuntimeTestResource("unbounded-concurrency", "0", "50000000", "false", "10000")
	unboundedSamples := prometheusReadRuntimeTestResource("unbounded-samples", "10", "0", "false", "10000")
	unboundedSearch := prometheusReadRuntimeTestResource("unbounded-search", "10", "50000000", "true", "0")
	searchDisabled := prometheusReadRuntimeTestResource("search-disabled", "10", "50000000", "false", "0")
	agent := prometheusReadRuntimeTestResource("agent", "0", "0", "true", "0")
	agent.Metadata[model.MetadataPrometheusAgentMode] = "true"
	unavailable := prometheusReadRuntimeTestResource("unavailable", "0", "0", "true", "0")
	unavailable.Metadata[model.MetadataPrometheusFlagsAvailable] = "false"
	wrongSource := prometheusReadRuntimeTestResource("wrong-source", "0", "0", "true", "0")
	wrongSource.Source.System = "thanos"
	missing := prometheusReadRuntimeTestResource("missing", "", "", "true", "")
	delete(missing.Metadata, model.MetadataPrometheusRemoteReadConcurrentLimit)
	delete(missing.Metadata, model.MetadataPrometheusRemoteReadSampleLimit)
	delete(missing.Metadata, model.MetadataPrometheusSearchMaxLimit)
	for _, resource := range []model.Resource{bounded, unboundedConcurrency, unboundedSamples, unboundedSearch, searchDisabled, agent, unavailable, wrongSource, missing} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert TSDB resource: %v", err)
		}
	}

	tests := []struct {
		name        string
		analyzer    Analyzer
		resourceID  string
		findingType string
	}{
		{"remote read concurrency", NewPrometheusUnboundedRemoteReadConcurrencyAnalyzer(), "unbounded-concurrency", "PrometheusUnboundedRemoteReadConcurrency"},
		{"remote read samples", NewPrometheusUnboundedRemoteReadSamplesAnalyzer(), "unbounded-samples", "PrometheusUnboundedRemoteReadSamples"},
		{"search API", NewPrometheusUnboundedSearchAPIAnalyzer(), "unbounded-search", "PrometheusUnboundedSearchAPI"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
			if err != nil {
				t.Fatalf("execute analyzer: %v", err)
			}
			if len(findings) != 1 ||
				findings[0].Resource.ID != test.resourceID ||
				findings[0].Type != test.findingType ||
				findings[0].Severity != model.SeverityWarning ||
				findings[0].Category != model.FindingCategoryCost ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryCost {
				t.Fatalf("unexpected findings: %#v", findings)
			}
		})
	}
}

func prometheusReadRuntimeTestResource(id, concurrentLimit, sampleLimit, searchEnabled, searchLimit string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTSDB,
		Name:   "prometheus TSDB",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "test"},
		Metadata: map[string]string{
			model.MetadataPrometheusFlagsAvailable:            "true",
			model.MetadataPrometheusAgentMode:                 "false",
			model.MetadataPrometheusRemoteReadConcurrentLimit: concurrentLimit,
			model.MetadataPrometheusRemoteReadSampleLimit:     sampleLimit,
			model.MetadataPrometheusSearchAPIEnabled:          searchEnabled,
			model.MetadataPrometheusSearchMaxLimit:            searchLimit,
		},
	}
}
