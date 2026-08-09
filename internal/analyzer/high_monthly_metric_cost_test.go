package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestHighMonthlyMetricCostAnalyzerRequiresExplicitPricingAndGuardrail(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	if err := store.Resources.Upsert(ctx, model.Resource{
		ID: "metric", Type: model.ResourceTypeMetric, Name: "api_requests_total",
		Source: model.SourceInfo{System: "prometheus"}, Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataSeriesCount:       "1250000",
			model.MetadataSeriesCountSource: "tsdb_head",
		},
	}); err != nil {
		t.Fatal(err)
	}
	item := NewHighMonthlyMetricCostAnalyzer()
	for _, config := range []map[string]any{
		{},
		{"cost_monthly_price_per_million_series": 100.0},
		{"cost_metric_monthly_guardrail": 50.0},
	} {
		findings, err := item.Execute(ctx, Context{Resources: store.Resources, Config: config})
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected disabled analyzer for config %#v, got %#v", config, findings)
		}
	}
}

func TestHighMonthlyMetricCostAnalyzerReportsMeasuredMetricAboveGuardrail(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	if err := store.Resources.Upsert(ctx, model.Resource{
		ID: "metric", Type: model.ResourceTypeMetric, Name: "api_requests_total",
		Source: model.SourceInfo{System: "prometheus"}, Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataSeriesCount:       "1250000",
			model.MetadataSeriesCountSource: "tsdb_head",
		},
	}); err != nil {
		t.Fatal(err)
	}
	findings, err := NewHighMonthlyMetricCostAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config: map[string]any{
			"cost_currency":                         "EUR",
			"cost_monthly_price_per_million_series": 100.0,
			"cost_metric_monthly_guardrail":         50.0,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %#v", findings)
	}
	finding := findings[0]
	if finding.Type != "HighMonthlyMetricCost" || finding.Metadata["estimated_monthly_cost"] != "125.00" ||
		finding.Metadata["monthly_cost_guardrail"] != "50.00" || finding.Metadata["currency"] != "EUR" ||
		finding.Metadata["series_count_source"] != "tsdb_head" {
		t.Fatalf("unexpected finding %#v", finding)
	}
}
