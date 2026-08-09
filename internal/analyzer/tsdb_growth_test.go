package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestTSDBGrowthAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{ID: "tsdb-growing", Type: model.ResourceTypeTSDB, Name: "growing", Source: model.SourceInfo{System: "prometheus", Instance: "http://prometheus:9090"}, Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataTSDBHeadSeries: "1300000", model.MetadataTSDBLabelMemoryBytes: "130000000"}},
		{ID: "tsdb-stable", Type: model.ResourceTypeTSDB, Name: "stable", Source: model.SourceInfo{System: "thanos", Instance: "http://thanos:10902"}, Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataTSDBHeadSeries: "1050", model.MetadataTSDBLabelMemoryBytes: "1050"}},
		{ID: "tsdb-old", Type: model.ResourceTypeTSDB, Name: "old", Status: model.ResourceStatusDeprecated, Metadata: map[string]string{model.MetadataTSDBHeadSeries: "9000000", model.MetadataTSDBLabelMemoryBytes: "900000000"}},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	baselineAt := time.Now().UTC().Add(-time.Hour)
	if err := store.ReportExports.Save(ctx, model.ReportExport{
		ID: "cost-baseline", Type: "cost", Format: "json", CreatedAt: baselineAt,
		Content: `{"tsdb_instances":[{"id":"tsdb-growing","system":"prometheus","instance":"http://prometheus:9090","head_series":1000000,"label_memory_bytes":100000000},{"id":"old-id","system":"thanos","instance":"http://thanos:10902","head_series":1000,"label_memory_bytes":1000}]}`,
	}); err != nil {
		t.Fatalf("save baseline: %v", err)
	}

	findings, err := NewTSDBGrowthAnalyzer().Execute(ctx, Context{Resources: store.Resources, ReportExports: store.ReportExports})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != "tsdb-growing" || len(findings[0].Evidence) != 2 {
		t.Fatalf("expected one series and memory growth finding, got %#v", findings)
	}
	if findings[0].Metadata["series_growth_delta"] != "300000" || findings[0].Metadata["label_memory_growth_delta"] != "30000000" || findings[0].Metadata["baseline_at"] == "" {
		t.Fatalf("unexpected growth evidence metadata: %#v", findings[0].Metadata)
	}
}

func TestTSDBGrowthAnalyzerUsesLatestValidSnapshotWithinLookback(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := model.Resource{ID: "tsdb-current", Type: model.ResourceTypeTSDB, Name: "current", Source: model.SourceInfo{System: "prometheus", Instance: "local"}, Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataTSDBHeadSeries: "120", model.MetadataTSDBLabelMemoryBytes: "220"}}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	now := time.Now().UTC()
	exports := []model.ReportExport{
		{ID: "stale", Type: "cost", Format: "json", CreatedAt: now.Add(-48 * time.Hour), Content: `{"tsdb_instances":[{"id":"tsdb-current","head_series":1,"label_memory_bytes":1}]}`},
		{ID: "malformed-latest", Type: "cost", Format: "json", CreatedAt: now.Add(-30 * time.Minute), Content: `{`},
		{ID: "valid", Type: "cost", Format: "json", CreatedAt: now.Add(-time.Hour), Content: `{"tsdb_instances":[{"id":"tsdb-current","head_series":100,"label_memory_bytes":200}]}`},
	}
	for _, export := range exports {
		if err := store.ReportExports.Save(ctx, export); err != nil {
			t.Fatalf("save export: %v", err)
		}
	}
	findings, err := NewTSDBGrowthAnalyzer().Execute(ctx, Context{
		Resources:     store.Resources,
		ReportExports: store.ReportExports,
		Config: map[string]any{
			"tsdb_growth_lookback":                     "2h",
			"tsdb_series_growth_ratio_threshold":       0.1,
			"tsdb_series_growth_minimum":               10,
			"tsdb_label_memory_growth_ratio_threshold": 0.05,
			"tsdb_label_memory_growth_minimum_bytes":   10,
		},
	})
	if err != nil || len(findings) != 1 {
		t.Fatalf("expected latest valid baseline finding, findings=%#v err=%v", findings, err)
	}
	if findings[0].Metadata["previous_head_series"] != "100" || findings[0].Metadata["previous_label_memory_bytes"] != "200" {
		t.Fatalf("expected valid baseline values, got %#v", findings[0].Metadata)
	}
}

func TestTSDBGrowthAnalyzerWithoutHistory(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := model.Resource{ID: "tsdb", Type: model.ResourceTypeTSDB, Name: "tsdb", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataTSDBHeadSeries: "2000000"}}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	findings, err := NewTSDBGrowthAnalyzer().Execute(ctx, Context{Resources: store.Resources, ReportExports: store.ReportExports})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected no finding without baseline, findings=%#v err=%v", findings, err)
	}
}
