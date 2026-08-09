package report

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBuildCostMetricDriftSummaryRequiresNewerSameSourceMeasurement(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	if err := store.Resources.Upsert(ctx, model.Resource{
		ID: "stale", Type: model.ResourceTypeMetric, Name: "stale",
		Source: model.SourceInfo{System: "prometheus"}, Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataConnectorID:       "prometheus.main",
			model.MetadataSeriesCountSource: "tsdb_head",
			model.MetadataSeriesCount:       "2000",
		},
	}); err != nil {
		t.Fatal(err)
	}
	baselineAt := time.Now().UTC()
	if err := store.ReportExports.Save(ctx, model.ReportExport{
		ID: "baseline", Type: "cost", Format: "json", CreatedAt: baselineAt,
		Content: `{"cost_metric_series":[
			{"resource":{"id":"growing","type":"Metric","name":"growing"},"connector_id":"prometheus.main","measurement_source":"tsdb_head","series":1000},
			{"resource":{"id":"wrong-source","type":"Metric","name":"wrong"},"connector_id":"prometheus.main","measurement_source":"recent_1h","series":1000},
			{"resource":{"id":"stale","type":"Metric","name":"stale"},"connector_id":"prometheus.main","measurement_source":"tsdb_head","series":1000}
		]}`,
	}); err != nil {
		t.Fatal(err)
	}
	// MemoryResourceRepository assigns UpdatedAt from the system clock. Cross a
	// clock tick so the new measurements are unambiguously after the baseline.
	time.Sleep(time.Millisecond)
	for _, resource := range []model.Resource{
		{
			ID: "growing", Type: model.ResourceTypeMetric, Name: "growing",
			Source: model.SourceInfo{System: "prometheus"}, Status: model.ResourceStatusActive,
			UpdatedAt: baselineAt.Add(time.Minute),
			Metadata: map[string]string{
				model.MetadataConnectorID:       "prometheus.main",
				model.MetadataSeriesCountSource: "tsdb_head",
				model.MetadataSeriesCount:       "1500",
			},
		},
		{
			ID: "wrong-source", Type: model.ResourceTypeMetric, Name: "wrong",
			Source: model.SourceInfo{System: "prometheus"}, Status: model.ResourceStatusActive,
			UpdatedAt: baselineAt.Add(time.Minute),
			Metadata: map[string]string{
				model.MetadataConnectorID:       "prometheus.main",
				model.MetadataSeriesCountSource: "tsdb_head",
				model.MetadataSeriesCount:       "2000",
			},
		},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := BuildCostMetricDriftSummary(ctx, store, storage.ResourceFilter{}, CostPricing{
		Currency: "USD", MonthlyPerMillionActiveSeries: 100,
	}, CostMetricDriftConfig{Lookback: 2 * time.Hour, GrowthRatioThreshold: 0.2, GrowthMinimum: 400})
	if err != nil {
		t.Fatal(err)
	}
	if !summary.BaselineFound || summary.ComparedMetricCount != 1 ||
		summary.DriftMetricCount != 1 || summary.SeriesIncrease != 500 ||
		len(summary.Items) != 1 || summary.Items[0].Resource.ID != "growing" ||
		summary.MonthlyCostIncrease == nil || *summary.MonthlyCostIncrease != 0.05 {
		t.Fatalf("unexpected drift summary %#v", summary)
	}
}

func TestLatestCostMetricSeriesBaselinesSkipsMalformedAndStaleExports(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	for _, export := range []model.ReportExport{
		{ID: "stale", Type: "cost", Format: "json", CreatedAt: now.Add(-48 * time.Hour), Content: `{"cost_metric_series":[{"resource":{"id":"stale","type":"Metric"},"connector_id":"c","measurement_source":"s","series":1}]}`},
		{ID: "malformed", Type: "cost", Format: "json", CreatedAt: now.Add(-time.Minute), Content: `{`},
		{ID: "valid", Type: "cost", Format: "json", CreatedAt: now.Add(-time.Hour), Content: `{"cost_metric_series":[{"resource":{"id":"metric","type":"Metric"},"connector_id":"c","measurement_source":"s","series":100}]}`},
	} {
		if err := store.ReportExports.Save(ctx, export); err != nil {
			t.Fatal(err)
		}
	}
	baseline, at, err := LatestCostMetricSeriesBaselines(ctx, store.ReportExports, now.Add(-2*time.Hour))
	if err != nil || len(baseline) != 1 || baseline["metric"].Series != 100 || !at.Equal(now.Add(-time.Hour)) {
		t.Fatalf("unexpected baseline=%#v at=%s err=%v", baseline, at, err)
	}
}

func TestLatestCostMetricSeriesBaselinesSelectsNewestSnapshotPerMetric(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	olderAt := now.Add(-2 * time.Hour)
	newerAt := now.Add(-time.Hour)
	for _, export := range []model.ReportExport{
		{
			ID: "global", Type: "cost", Format: "json", CreatedAt: olderAt,
			Content: `{"cost_metric_series":[
				{"resource":{"id":"team-a","type":"Metric"},"connector_id":"c","measurement_source":"s","series":100},
				{"resource":{"id":"team-b","type":"Metric"},"connector_id":"c","measurement_source":"s","series":200}
			]}`,
		},
		{
			ID: "team-a-only", Type: "cost", Format: "json", CreatedAt: newerAt,
			Content: `{"cost_metric_series":[
				{"resource":{"id":"team-a","type":"Metric"},"connector_id":"c","measurement_source":"s","series":150}
			]}`,
		},
	} {
		if err := store.ReportExports.Save(ctx, export); err != nil {
			t.Fatal(err)
		}
	}
	baselines, latestAt, err := LatestCostMetricSeriesBaselines(ctx, store.ReportExports, now.Add(-24*time.Hour))
	if err != nil || len(baselines) != 2 || baselines["team-a"].Series != 150 ||
		baselines["team-b"].Series != 200 || !baselines["team-a"].SnapshotAt.Equal(newerAt) ||
		!baselines["team-b"].SnapshotAt.Equal(olderAt) || !latestAt.Equal(newerAt) {
		t.Fatalf("unexpected per-Metric baselines=%#v latest=%s err=%v", baselines, latestAt, err)
	}
}

func TestBuildCostMetricSeriesSnapshotExcludesUntrustedMeasurements(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		{
			ID: "valid", Type: model.ResourceTypeMetric, Name: "valid", Status: model.ResourceStatusActive,
			Metadata: map[string]string{
				model.MetadataConnectorID:       "c",
				model.MetadataSeriesCountSource: "tsdb_head",
				model.MetadataSeriesCount:       "100",
			},
		},
		{
			ID: "missing-source", Type: model.ResourceTypeMetric, Name: "missing", Status: model.ResourceStatusActive,
			Metadata: map[string]string{model.MetadataConnectorID: "c", model.MetadataSeriesCount: "100"},
		},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	items, err := BuildCostMetricSeriesSnapshot(ctx, store, storage.ResourceFilter{})
	if err != nil || len(items) != 1 || items[0].Resource.ID != "valid" {
		t.Fatalf("unexpected snapshot %#v err=%v", items, err)
	}
}
