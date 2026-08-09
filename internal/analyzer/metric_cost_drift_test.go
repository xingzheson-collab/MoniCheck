package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestMetricCostDriftAnalyzerUsesSavedCostSnapshot(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	baselineAt := time.Now().UTC().Add(-time.Hour)
	if err := store.ReportExports.Save(ctx, model.ReportExport{
		ID: "baseline", Type: "cost", Format: "json", CreatedAt: baselineAt,
		Content: `{"cost_metric_series":[{"resource":{"id":"metric","type":"Metric","name":"requests"},"connector_id":"prometheus.main","measurement_source":"tsdb_head","series":1000}]}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Resources.Upsert(ctx, model.Resource{
		ID: "metric", Type: model.ResourceTypeMetric, Name: "requests", Status: model.ResourceStatusActive,
		UpdatedAt: baselineAt.Add(time.Minute),
		Metadata: map[string]string{
			model.MetadataConnectorID:       "prometheus.main",
			model.MetadataSeriesCountSource: "tsdb_head",
			model.MetadataSeriesCount:       "1600",
		},
	}); err != nil {
		t.Fatal(err)
	}
	findings, err := NewMetricCostDriftAnalyzer().Execute(ctx, Context{
		Resources: store.Resources, ReportExports: store.ReportExports,
		Config: map[string]any{
			"cost_metric_drift_lookback":         "2h",
			"cost_metric_growth_ratio_threshold": 0.2,
			"cost_metric_growth_minimum":         500,
		},
	})
	if err != nil || len(findings) != 1 {
		t.Fatalf("expected drift finding, findings=%#v err=%v", findings, err)
	}
	finding := findings[0]
	if finding.Type != "RapidMetricCostGrowth" || finding.Category != "" ||
		finding.Metadata["baseline_series"] != "1000" ||
		finding.Metadata["current_series"] != "1600" ||
		finding.Metadata["series_growth_delta"] != "600" {
		t.Fatalf("unexpected finding %#v", finding)
	}
}

func TestMetricCostDriftAnalyzerRejectsNonComparableMeasurement(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	baselineAt := time.Now().UTC().Add(-time.Hour)
	if err := store.ReportExports.Save(ctx, model.ReportExport{
		ID: "baseline", Type: "cost", Format: "json", CreatedAt: baselineAt,
		Content: `{"cost_metric_series":[{"resource":{"id":"metric","type":"Metric"},"connector_id":"old","measurement_source":"tsdb_head","series":1000}]}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Resources.Upsert(ctx, model.Resource{
		ID: "metric", Type: model.ResourceTypeMetric, Name: "requests", Status: model.ResourceStatusActive,
		UpdatedAt: baselineAt.Add(time.Minute),
		Metadata: map[string]string{
			model.MetadataConnectorID:       "new",
			model.MetadataSeriesCountSource: "tsdb_head",
			model.MetadataSeriesCount:       "5000",
		},
	}); err != nil {
		t.Fatal(err)
	}
	findings, err := NewMetricCostDriftAnalyzer().Execute(ctx, Context{
		Resources: store.Resources, ReportExports: store.ReportExports,
	})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected connector mismatch to be skipped, findings=%#v err=%v", findings, err)
	}
}
