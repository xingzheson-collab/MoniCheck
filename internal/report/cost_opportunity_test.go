package report

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBuildCostOpportunitySummaryQuantifiesAndDeduplicatesMetrics(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{
			ID: "metric-unused", Type: model.ResourceTypeMetric, Name: "legacy_requests_total",
			Source: model.SourceInfo{System: "prometheus"}, Status: model.ResourceStatusActive,
			Metadata: map[string]string{model.MetadataSeriesCount: "250000", model.MetadataSeriesCountSource: "tsdb_head"},
			Labels:   map[string]string{"team": "platform"},
		},
		{
			ID: "metric-cardinality", Type: model.ResourceTypeMetric, Name: "request_events_total",
			Source: model.SourceInfo{System: "prometheus"}, Status: model.ResourceStatusActive,
			Metadata: map[string]string{model.MetadataSeriesCount: "1600000", model.MetadataSeriesCountSource: "recent_1h"},
			Labels:   map[string]string{"team": "platform"},
		},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	findings := []model.Finding{
		{ID: "unused", Type: "UnusedMetric", Severity: model.SeverityWarning, Resource: model.ResourceRef{ID: "metric-unused", Type: model.ResourceTypeMetric, Name: "legacy_requests_total"}, Status: model.FindingStatusOpen, Metadata: map[string]string{"analyzer_id": "unused"}},
		{ID: "unused-high", Type: "HighCardinalityMetric", Severity: model.SeverityWarning, Resource: model.ResourceRef{ID: "metric-unused", Type: model.ResourceTypeMetric, Name: "legacy_requests_total"}, Status: model.FindingStatusOpen, Metadata: map[string]string{"analyzer_id": "high", "threshold": "100000"}},
		{ID: "high", Type: "HighCardinalityMetric", Severity: model.SeverityWarning, Resource: model.ResourceRef{ID: "metric-cardinality", Type: model.ResourceTypeMetric, Name: "request_events_total"}, Status: model.FindingStatusAcked, Metadata: map[string]string{"analyzer_id": "high", "threshold": "1000000"}},
	}
	for _, finding := range findings {
		if err := store.Findings.ReplaceOpenByAnalyzer(ctx, finding.Metadata["analyzer_id"]+"."+finding.ID, []model.Finding{finding}); err != nil {
			t.Fatal(err)
		}
	}

	summary, err := BuildCostOpportunitySummary(ctx, store, storage.ResourceFilter{Team: "platform"}, CostPricing{
		Currency: "usd", MonthlyPerMillionActiveSeries: 120,
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.OpportunityCount != 2 || summary.QuantifiedCount != 2 {
		t.Fatalf("unexpected opportunity counts: %#v", summary)
	}
	if summary.CurrentSeries != 1850000 || summary.PotentialSeriesReduction != 850000 {
		t.Fatalf("unexpected series totals: %#v", summary)
	}
	if !summary.PricingConfigured || summary.Currency != "USD" || summary.PotentialMonthlySavings == nil || *summary.PotentialMonthlySavings != 102 {
		t.Fatalf("unexpected pricing summary: %#v", summary)
	}
	if summary.Items[0].OpportunityType != "REDUCE_HIGH_CARDINALITY" || summary.Items[0].PotentialSeriesReduction != 600000 {
		t.Fatalf("expected opportunities sorted by reduction: %#v", summary.Items)
	}
	if summary.Items[1].OpportunityType != "REMOVE_UNUSED_METRIC" || summary.Items[1].PotentialSeriesReduction != 250000 {
		t.Fatalf("expected unused metric to supersede duplicate high-cardinality estimate: %#v", summary.Items)
	}
}

func TestBuildCostOpportunitySummaryExcludesUnpricedStaleAndOutOfScopeItems(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		{ID: "active", Type: model.ResourceTypeMetric, Name: "active", Status: model.ResourceStatusActive, Labels: map[string]string{"team": "platform"}, Metadata: map[string]string{model.MetadataSeriesCount: "900", model.MetadataSeriesCountSource: "tsdb_head"}},
		{ID: "other", Type: model.ResourceTypeMetric, Name: "other", Status: model.ResourceStatusActive, Labels: map[string]string{"team": "payments"}, Metadata: map[string]string{model.MetadataSeriesCount: "5000", model.MetadataSeriesCountSource: "tsdb_head"}},
		{ID: "deleted", Type: model.ResourceTypeMetric, Name: "deleted", Status: model.ResourceStatusDeleted, Labels: map[string]string{"team": "platform"}, Metadata: map[string]string{model.MetadataSeriesCount: "5000"}},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	findings := []model.Finding{
		{ID: "stale-high", Type: "HighCardinalityMetric", Resource: model.ResourceRef{ID: "active", Type: model.ResourceTypeMetric}, Status: model.FindingStatusOpen, Metadata: map[string]string{"analyzer_id": "a", "threshold": "1000"}},
		{ID: "other-unused", Type: "UnusedMetric", Resource: model.ResourceRef{ID: "other", Type: model.ResourceTypeMetric}, Status: model.FindingStatusOpen, Metadata: map[string]string{"analyzer_id": "b"}},
		{ID: "deleted-unused", Type: "UnusedMetric", Resource: model.ResourceRef{ID: "deleted", Type: model.ResourceTypeMetric}, Status: model.FindingStatusOpen, Metadata: map[string]string{"analyzer_id": "c"}},
		{ID: "closed", Type: "UnusedMetric", Resource: model.ResourceRef{ID: "active", Type: model.ResourceTypeMetric}, Status: model.FindingStatusClosed, Metadata: map[string]string{"analyzer_id": "d"}},
	}
	for _, finding := range findings {
		if err := store.Findings.ReplaceOpenByAnalyzer(ctx, finding.Metadata["analyzer_id"], []model.Finding{finding}); err != nil {
			t.Fatal(err)
		}
	}

	summary, err := BuildCostOpportunitySummary(ctx, store, storage.ResourceFilter{Team: "platform"}, CostPricing{})
	if err != nil {
		t.Fatal(err)
	}
	if summary.OpportunityCount != 0 || summary.PotentialMonthlySavings != nil || summary.PricingConfigured {
		t.Fatalf("expected no stale, closed, inactive, or out-of-scope opportunities: %#v", summary)
	}
	if summary.Currency != "USD" || summary.MonthlyPricePerMillion != 0 || summary.Items == nil {
		t.Fatalf("expected explicit unpriced contract and non-nil items: %#v", summary)
	}
}
