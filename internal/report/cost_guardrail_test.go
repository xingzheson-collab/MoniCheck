package report

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBuildCostGuardrailSummaryEvaluatesBudgetAndMetricGuardrail(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	for _, resource := range []model.Resource{
		{
			ID: "api", Type: model.ResourceTypeMetric, Name: "api_requests_total",
			Source: model.SourceInfo{System: "prometheus"},
			Status: model.ResourceStatusActive, UpdatedAt: now,
			Metadata: map[string]string{
				model.MetadataSeriesCount:       "1250000",
				model.MetadataSeriesCountSource: "tsdb_head",
				model.MetadataConnectorID:       "prometheus.primary",
			},
		},
		{
			ID: "worker", Type: model.ResourceTypeMetric, Name: "worker_queue_depth",
			Source: model.SourceInfo{System: "prometheus"},
			Status: model.ResourceStatusActive, UpdatedAt: now,
			Metadata: map[string]string{model.MetadataSeriesCount: "250000"},
		},
		{
			ID: "unknown", Type: model.ResourceTypeMetric, Name: "unknown_metric",
			Source: model.SourceInfo{System: "prometheus"},
			Status: model.ResourceStatusActive, UpdatedAt: now,
		},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := BuildCostGuardrailSummary(ctx, store, storage.ResourceFilter{}, CostPricing{
		Currency: "USD", MonthlyPerMillionActiveSeries: 100,
	}, CostGuardrailConfig{MonthlyBudget: 120, MetricMonthlyGuardrail: 50})
	if err != nil {
		t.Fatal(err)
	}
	if summary.MetricCount != 3 || summary.QuantifiedMetricCount != 2 ||
		summary.MeasuredSeries != 1500000 || summary.MeasuredMonthlyCost == nil ||
		*summary.MeasuredMonthlyCost != 150 || summary.BudgetState != CostBudgetStateExceeded ||
		summary.BudgetVariance == nil || *summary.BudgetVariance != 30 ||
		summary.BudgetUtilizationPercent == nil || *summary.BudgetUtilizationPercent != 125 ||
		summary.ExceededMetricCount != 1 || len(summary.Items) != 2 {
		t.Fatalf("unexpected summary %#v", summary)
	}
	if summary.Items[0].Resource.ID != "api" || summary.Items[0].MonthlyCost != 125 ||
		summary.Items[0].GuardrailState != CostMetricGuardrailStateExceeded {
		t.Fatalf("unexpected top metric %#v", summary.Items[0])
	}
}

func TestBuildCostGuardrailSummaryIsExplicitlyDisabledWithoutPricing(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	if err := store.Resources.Upsert(ctx, model.Resource{
		ID: "metric", Type: model.ResourceTypeMetric, Name: "metric",
		Source: model.SourceInfo{System: "prometheus"}, Status: model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataSeriesCount: "1000"},
	}); err != nil {
		t.Fatal(err)
	}
	summary, err := BuildCostGuardrailSummary(ctx, store, storage.ResourceFilter{}, CostPricing{}, CostGuardrailConfig{
		MonthlyBudget: 100, MetricMonthlyGuardrail: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.BudgetState != CostBudgetStateUnpriced || summary.MeasuredMonthlyCost != nil ||
		summary.ExceededMetricCount != 0 || len(summary.Items) != 0 {
		t.Fatalf("expected unpriced summary, got %#v", summary)
	}
}
