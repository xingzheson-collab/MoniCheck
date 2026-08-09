package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusQueryRuntimeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		prometheusQueryRuntimeTestResource("defaults", "20", "50000000", "120", "300"),
		prometheusQueryRuntimeTestResource("high-concurrency", "40", "50000000", "120", "300"),
		prometheusQueryRuntimeTestResource("high-samples", "20", "100000000", "120", "300"),
		prometheusQueryRuntimeTestResource("long-timeout", "20", "50000000", "300", "300"),
		prometheusQueryRuntimeTestResource("long-lookback", "20", "50000000", "120", "600"),
	}
	saturation := prometheusQueryRuntimeTestResource("saturation", "20", "50000000", "120", "300")
	saturation.Metadata[model.MetadataPrometheusConcurrentRuleEval] = "true"
	saturation.Metadata[model.MetadataPrometheusRuleMaxConcurrentEvals] = "20"
	saturation.Metadata[model.MetadataPrometheusQueryConcurrencyHeadroom] = "0"
	headroom := prometheusQueryRuntimeTestResource("headroom", "20", "50000000", "120", "300")
	headroom.Metadata[model.MetadataPrometheusConcurrentRuleEval] = "true"
	headroom.Metadata[model.MetadataPrometheusRuleMaxConcurrentEvals] = "4"
	headroom.Metadata[model.MetadataPrometheusQueryConcurrencyHeadroom] = "16"
	featureDisabled := prometheusQueryRuntimeTestResource("feature-disabled", "20", "50000000", "120", "300")
	featureDisabled.Metadata[model.MetadataPrometheusConcurrentRuleEval] = "false"
	featureDisabled.Metadata[model.MetadataPrometheusRuleMaxConcurrentEvals] = "20"
	featureDisabled.Metadata[model.MetadataPrometheusQueryConcurrencyHeadroom] = "0"
	unavailable := prometheusQueryRuntimeTestResource("unavailable", "40", "100000000", "300", "600")
	unavailable.Metadata[model.MetadataPrometheusFlagsAvailable] = "false"
	wrongSource := prometheusQueryRuntimeTestResource("wrong-source", "40", "100000000", "300", "600")
	wrongSource.Source.System = "thanos"
	missing := prometheusQueryRuntimeTestResource("missing", "", "", "", "")
	agent := prometheusQueryRuntimeTestResource("agent", "40", "100000000", "300", "600")
	agent.Metadata[model.MetadataPrometheusAgentMode] = "true"
	agent.Metadata[model.MetadataPrometheusConcurrentRuleEval] = "true"
	agent.Metadata[model.MetadataPrometheusRuleMaxConcurrentEvals] = "40"
	agent.Metadata[model.MetadataPrometheusQueryConcurrencyHeadroom] = "0"
	resources = append(resources, saturation, headroom, featureDisabled, unavailable, wrongSource, missing, agent)
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert TSDB resource: %v", err)
		}
	}

	tests := []struct {
		name        string
		analyzer    Analyzer
		resourceID  string
		findingType string
		category    model.FindingCategory
	}{
		{"concurrency", NewPrometheusHighQueryConcurrencyAnalyzer(), "high-concurrency", "PrometheusHighQueryConcurrency", model.FindingCategoryCost},
		{"samples", NewPrometheusHighQuerySampleLimitAnalyzer(), "high-samples", "PrometheusHighQuerySampleLimit", model.FindingCategoryCost},
		{"timeout", NewPrometheusLongQueryTimeoutAnalyzer(), "long-timeout", "PrometheusLongQueryTimeout", model.FindingCategoryCost},
		{"lookback", NewPrometheusLongQueryLookbackAnalyzer(), "long-lookback", "PrometheusLongQueryLookback", model.FindingCategoryReliability},
		{"rule saturation", NewPrometheusRuleQuerySaturationAnalyzer(), "saturation", "PrometheusRuleQuerySaturationRisk", model.FindingCategoryReliability},
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
				findings[0].Category != test.category ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != test.category {
				t.Fatalf("unexpected findings: %#v", findings)
			}
		})
	}
}

func TestPrometheusQueryRuntimeAnalyzerThresholdOverrides(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := prometheusQueryRuntimeTestResource("custom", "40", "100000000", "300", "600")
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert TSDB resource: %v", err)
	}
	config := map[string]any{
		"kubernetes_query_max_concurrency_threshold": 50,
		"kubernetes_query_max_samples_threshold":     150_000_000,
		"kubernetes_query_timeout_threshold":         "10m",
		"kubernetes_query_lookback_threshold":        "15m",
	}
	for _, item := range []Analyzer{
		NewPrometheusHighQueryConcurrencyAnalyzer(),
		NewPrometheusHighQuerySampleLimitAnalyzer(),
		NewPrometheusLongQueryTimeoutAnalyzer(),
		NewPrometheusLongQueryLookbackAnalyzer(),
	} {
		findings, err := item.Execute(ctx, Context{Resources: store.Resources, Config: config})
		if err != nil {
			t.Fatalf("execute %s: %v", item.ID(), err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected custom threshold to suppress %s, got %#v", item.ID(), findings)
		}
	}
}

func prometheusQueryRuntimeTestResource(id, concurrency, samples, timeout, lookback string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTSDB,
		Name:   "prometheus TSDB",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "test"},
		Metadata: map[string]string{
			model.MetadataPrometheusFlagsAvailable:       "true",
			model.MetadataPrometheusAgentMode:            "false",
			model.MetadataPrometheusQueryMaxConcurrency:  concurrency,
			model.MetadataPrometheusQueryMaxSamples:      samples,
			model.MetadataPrometheusQueryTimeoutSeconds:  timeout,
			model.MetadataPrometheusQueryLookbackSeconds: lookback,
		},
	}
}
