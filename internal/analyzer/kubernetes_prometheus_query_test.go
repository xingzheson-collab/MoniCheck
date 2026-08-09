package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestKubernetesPrometheusQueryAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	valid := kubernetesPrometheusQueryResource("valid")
	invalid := kubernetesPrometheusQueryResource("invalid")
	invalid.Metadata["prometheus_query_invalid_setting_count"] = "2"
	concurrency := kubernetesPrometheusQueryResource("concurrency")
	concurrency.Metadata["prometheus_query_max_concurrency"] = "40"
	samples := kubernetesPrometheusQueryResource("samples")
	samples.Metadata["prometheus_query_max_samples"] = "100000000"
	timeout := kubernetesPrometheusQueryResource("timeout")
	timeout.Metadata["prometheus_query_timeout_seconds"] = "300"
	lookback := kubernetesPrometheusQueryResource("lookback")
	lookback.Metadata["prometheus_query_lookback_seconds"] = "600"
	gap := kubernetesPrometheusQueryResource("gap")
	gap.Metadata["prometheus_query_lookback_seconds"] = "15"
	gap.Metadata["prometheus_scrape_interval_seconds"] = "30"
	gap.Metadata["prometheus_query_lookback_below_scrape_interval"] = "true"
	agent := kubernetesPrometheusQueryResource("agent")
	agent.Metadata["kubernetes_kind"] = "PrometheusAgent"
	agent.Metadata["prometheus_query_invalid_setting_count"] = "1"
	for _, resource := range []model.Resource{valid, invalid, concurrency, samples, timeout, lookback, gap, agent} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	tests := []struct {
		name       string
		analyzer   Analyzer
		resourceID string
		category   model.FindingCategory
	}{
		{"invalid", NewKubernetesInvalidPrometheusQueryAnalyzer(), invalid.ID, model.FindingCategoryConfiguration},
		{"concurrency", NewKubernetesHighQueryConcurrencyAnalyzer(), concurrency.ID, model.FindingCategoryCost},
		{"samples", NewKubernetesHighQuerySampleLimitAnalyzer(), samples.ID, model.FindingCategoryCost},
		{"timeout", NewKubernetesLongQueryTimeoutAnalyzer(), timeout.ID, model.FindingCategoryCost},
		{"lookback", NewKubernetesLongQueryLookbackAnalyzer(), lookback.ID, model.FindingCategoryReliability},
		{"gap", NewKubernetesQueryLookbackBelowScrapeAnalyzer(), gap.ID, model.FindingCategoryReliability},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
			if err != nil || len(findings) != 1 || findings[0].Resource.ID != test.resourceID || findings[0].Category != test.category {
				t.Fatalf("unexpected findings: %#v err=%v", findings, err)
			}
		})
	}
}

func TestKubernetesPrometheusQueryAnalyzerThresholdOverrides(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := kubernetesPrometheusQueryResource("custom")
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	config := map[string]any{
		"kubernetes_query_max_concurrency_threshold": 10,
		"kubernetes_query_max_samples_threshold":     25_000_000,
		"kubernetes_query_timeout_threshold":         "1m",
		"kubernetes_query_lookback_threshold":        "2m",
	}
	for _, analyzer := range []Analyzer{NewKubernetesHighQueryConcurrencyAnalyzer(), NewKubernetesHighQuerySampleLimitAnalyzer(), NewKubernetesLongQueryTimeoutAnalyzer(), NewKubernetesLongQueryLookbackAnalyzer()} {
		findings, err := analyzer.Execute(ctx, Context{Resources: store.Resources, Config: config})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != resource.ID {
			t.Fatalf("unexpected custom-threshold findings for %s: %#v err=%v", analyzer.ID(), findings, err)
		}
	}
}

func kubernetesPrometheusQueryResource(name string) model.Resource {
	return model.Resource{ID: name, UID: name, Type: model.ResourceTypeTSDB, Name: "monitoring/" + name, Source: model.SourceInfo{System: "kubernetes"}, Status: model.ResourceStatusActive, Metadata: map[string]string{
		"kubernetes_kind":                                 "Prometheus",
		"namespace":                                       "monitoring",
		"prometheus_query_invalid_setting_count":          "0",
		"prometheus_query_max_concurrency":                "20",
		"prometheus_query_max_concurrency_declared":       "true",
		"prometheus_query_max_concurrency_valid":          "true",
		"prometheus_query_max_samples":                    "50000000",
		"prometheus_query_max_samples_declared":           "true",
		"prometheus_query_max_samples_valid":              "true",
		"prometheus_query_timeout_seconds":                "120",
		"prometheus_query_timeout_declared":               "true",
		"prometheus_query_timeout_valid":                  "true",
		"prometheus_query_lookback_seconds":               "300",
		"prometheus_query_lookback_declared":              "true",
		"prometheus_query_lookback_valid":                 "true",
		"prometheus_scrape_interval_seconds":              "30",
		"prometheus_query_lookback_below_scrape_interval": "false",
	}}
}
