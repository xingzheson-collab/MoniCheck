package report

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBuildCostPortfolioSummaryCombinesPotentialPendingAndVerifiedSavings(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	evaluatedAt := now.Add(4 * time.Hour)
	resources := []model.Resource{
		{
			ID: "potential", Type: model.ResourceTypeMetric, Name: "potential", Status: model.ResourceStatusActive,
			UpdatedAt: now,
			Metadata:  map[string]string{model.MetadataSeriesCount: "400000", model.MetadataSeriesCountSource: "tsdb_head"},
		},
		{
			ID: "pending", Type: model.ResourceTypeMetric, Name: "pending", Status: model.ResourceStatusActive,
			Metadata: map[string]string{model.MetadataSeriesCount: "300000", model.MetadataSeriesCountSource: "tsdb_head"},
		},
		{
			ID: "verified", Type: model.ResourceTypeMetric, Name: "verified", Status: model.ResourceStatusActive,
			UpdatedAt: now,
			Metadata:  map[string]string{model.MetadataSeriesCount: "100000", model.MetadataSeriesCountSource: "tsdb_head"},
		},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	findings := []model.Finding{
		{ID: "f-potential", Type: "UnusedMetric", Resource: model.ResourceRef{ID: "potential", Type: model.ResourceTypeMetric, Name: "potential"}, Status: model.FindingStatusOpen, Metadata: map[string]string{"analyzer_id": "potential"}},
		{ID: "f-pending", Type: "UnusedMetric", Resource: model.ResourceRef{ID: "pending", Type: model.ResourceTypeMetric, Name: "pending"}, Status: model.FindingStatusOpen, Metadata: map[string]string{"analyzer_id": "pending"}},
		{ID: "f-verified", Type: "UnusedMetric", Resource: model.ResourceRef{ID: "verified", Type: model.ResourceTypeMetric, Name: "verified"}, Status: model.FindingStatusOpen, Metadata: map[string]string{"analyzer_id": "verified"}},
	}
	for _, finding := range findings {
		if err := store.Findings.ReplaceOpenByAnalyzer(ctx, finding.Metadata["analyzer_id"], []model.Finding{finding}); err != nil {
			t.Fatal(err)
		}
	}
	for _, event := range []model.FindingWorkflowEvent{
		{
			ID: "pending-baseline", FindingID: "f-pending", Action: CostBaselineCapturedAction, CreatedAt: now.Add(2 * time.Hour),
			Metadata: map[string]string{"baseline_series": "300000", "potential_series_reduction": "300000", "measurement_source": "tsdb_head", "opportunity_type": "REMOVE_UNUSED_METRIC"},
		},
		{
			ID: "verified-baseline", FindingID: "f-verified", Action: CostBaselineCapturedAction, CreatedAt: now.Add(-2 * time.Hour),
			Metadata: map[string]string{"baseline_series": "300000", "potential_series_reduction": "300000", "measurement_source": "tsdb_head", "opportunity_type": "REMOVE_UNUSED_METRIC"},
		},
	} {
		if err := store.FindingWorkflow.Save(ctx, event); err != nil {
			t.Fatal(err)
		}
	}

	summary, err := BuildCostPortfolioSummaryAt(ctx, store, storage.ResourceFilter{}, CostPricing{
		Currency: "USD", MonthlyPerMillionActiveSeries: 100,
	}, time.Hour, evaluatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if summary.PortfolioCount != 3 || summary.PotentialCount != 1 || summary.BaselinedCount != 2 ||
		summary.PendingCount != 1 || summary.OverdueCount != 1 || summary.VerifiedCount != 1 {
		t.Fatalf("unexpected portfolio states %#v", summary)
	}
	if summary.PotentialSeriesReduction != 1_000_000 || summary.VerifiedSeriesReduction != 200000 ||
		summary.RealizationPercent != 20 || summary.PotentialMonthlySavings == nil ||
		*summary.PotentialMonthlySavings != 100 || summary.VerifiedMonthlySavings == nil ||
		*summary.VerifiedMonthlySavings != 20 {
		t.Fatalf("unexpected portfolio savings potential=%f verified=%f summary=%#v", *summary.PotentialMonthlySavings, *summary.VerifiedMonthlySavings, summary)
	}
	if !summary.Items[0].Overdue || summary.Items[0].FindingID != "f-pending" {
		t.Fatalf("expected overdue item first, got %#v", summary.Items)
	}
}

func TestBuildCostPortfolioSummaryPreservesBaselineAfterFindingRemoval(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	evaluatedAt := now.Add(4 * time.Hour)
	if err := store.Resources.Upsert(ctx, model.Resource{
		ID: "metric", Type: model.ResourceTypeMetric, Name: "metric", Status: model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataSeriesCount: "100", model.MetadataSeriesCountSource: "tsdb_head"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.FindingWorkflow.Save(ctx, model.FindingWorkflowEvent{
		ID: "baseline", FindingID: "removed-finding", Action: CostBaselineCapturedAction, CreatedAt: now.Add(2 * time.Hour),
		Metadata: map[string]string{
			"baseline_series": "100", "potential_series_reduction": "80", "measurement_source": "tsdb_head",
			"opportunity_type": "REMOVE_UNUSED_METRIC", "finding_type": "UnusedMetric",
			"resource_id": "metric", "resource_type": string(model.ResourceTypeMetric), "resource_name": "metric",
		},
	}); err != nil {
		t.Fatal(err)
	}
	summary, err := BuildCostPortfolioSummaryAt(ctx, store, storage.ResourceFilter{}, CostPricing{}, time.Hour, evaluatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if summary.PortfolioCount != 1 || summary.PotentialSeriesReduction != 80 ||
		summary.PendingCount != 1 || summary.OverdueCount != 1 {
		t.Fatalf("expected self-contained baseline in portfolio, got %#v", summary)
	}
}
