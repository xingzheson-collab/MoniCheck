package report

import (
	"context"
	"strings"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBuildCostAllocationSummaryPreservesDimensionTotalsAndUncertainty(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{
			ID: "payments", Type: model.ResourceTypeMetric, Name: "payments", Status: model.ResourceStatusActive,
			Labels:   map[string]string{"team": "payments", "project": "commerce"},
			Metadata: map[string]string{model.MetadataSeriesCount: "600000", model.MetadataSeriesCountSource: "tsdb_head"},
		},
		{
			ID: "platform", Type: model.ResourceTypeMetric, Name: "platform", Status: model.ResourceStatusActive,
			Labels:   map[string]string{"team": "platform"},
			Metadata: map[string]string{model.MetadataSeriesCount: "300000", model.MetadataSeriesCountSource: "tsdb_head"},
		},
		{
			ID: "unknown", Type: model.ResourceTypeMetric, Name: "unknown", Status: model.ResourceStatusActive,
			Metadata: map[string]string{model.MetadataSeriesCount: "100000", model.MetadataSeriesCountSource: "recent_1h"},
		},
		{
			ID: "conflict", Type: model.ResourceTypeMetric, Name: "conflict", Status: model.ResourceStatusActive,
			Labels:   map[string]string{"team": "alpha"},
			Metadata: map[string]string{"team": "beta", model.MetadataSeriesCount: "200000"},
		},
		{
			ID: "unmeasured", Type: model.ResourceTypeMetric, Name: "unmeasured", Status: model.ResourceStatusActive,
		},
		{
			ID: "orphan", Type: model.ResourceTypeMetric, Name: "orphan", Status: model.ResourceStatusOrphan,
			Labels:   map[string]string{"team": "ignored"},
			Metadata: map[string]string{model.MetadataSeriesCount: "900000"},
		},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}

	summary, err := BuildCostAllocationSummary(ctx, store, storage.ResourceFilter{}, CostPricing{
		Currency:                      "USD",
		MonthlyPerMillionActiveSeries: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.MetricCount != 5 || summary.QuantifiedMetricCount != 4 || summary.MeasuredSeries != 1200000 {
		t.Fatalf("unexpected allocation summary %#v", summary)
	}
	if summary.MeasuredMonthlyCost == nil || *summary.MeasuredMonthlyCost != 120 {
		t.Fatalf("unexpected priced measured cost %#v", summary)
	}
	team := costAllocationDimensionByName(t, summary, "team")
	if team.AllocatedSeries != 900000 || team.UnallocatedSeries != 100000 || team.AmbiguousSeries != 200000 || team.CoveragePercent != 75 {
		t.Fatalf("unexpected team allocation %#v", team)
	}
	var total int64
	for _, item := range team.Items {
		total += item.Series
	}
	if total != summary.MeasuredSeries {
		t.Fatalf("dimension must conserve measured series: got %d want %d", total, summary.MeasuredSeries)
	}
	if team.Items[0].Key != "payments" || team.Items[0].Series != 600000 || team.Items[0].MonthlyCost == nil || *team.Items[0].MonthlyCost != 60 {
		t.Fatalf("expected largest allocated bucket first, got %#v", team.Items)
	}
	export, err := BuildExportWithFilterAndCostPricing(ctx, store, "cost", "csv", storage.ResourceFilter{}, CostPricing{
		Currency:                      "USD",
		MonthlyPerMillionActiveSeries: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"cost_allocation_summary,measured_series,1200000",
		"cost_allocation_dimension,team.coverage_percent,75.00",
		"cost_allocation,team.ALLOCATED.payments.series,600000",
		"cost_allocation,team.AMBIGUOUS.Ambiguous.series,200000",
	} {
		if !strings.Contains(export.Content, expected) {
			t.Fatalf("expected CSV allocation %q in:\n%s", expected, export.Content)
		}
	}
}

func TestBuildCostAllocationSummaryAppliesTenantFilterBeforeAllocation(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		{ID: "a", Type: model.ResourceTypeMetric, Status: model.ResourceStatusActive, Labels: map[string]string{"team": "alpha"}, Metadata: map[string]string{model.MetadataSeriesCount: "100"}},
		{ID: "b", Type: model.ResourceTypeMetric, Status: model.ResourceStatusActive, Labels: map[string]string{"team": "beta"}, Metadata: map[string]string{model.MetadataSeriesCount: "900"}},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := BuildCostAllocationSummary(ctx, store, storage.ResourceFilter{Team: "alpha"}, CostPricing{})
	if err != nil {
		t.Fatal(err)
	}
	if summary.MeasuredSeries != 100 || summary.MetricCount != 1 {
		t.Fatalf("expected tenant filter before allocation, got %#v", summary)
	}
}

func costAllocationDimensionByName(t *testing.T, summary CostAllocationSummary, name string) CostAllocationDimension {
	t.Helper()
	for _, dimension := range summary.Dimensions {
		if dimension.Name == name {
			return dimension
		}
	}
	t.Fatalf("missing allocation dimension %q", name)
	return CostAllocationDimension{}
}
