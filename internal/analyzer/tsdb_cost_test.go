package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestTSDBCostAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{ID: "tsdb-small", Type: model.ResourceTypeTSDB, Name: "small", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataTSDBHeadSeries: "100", model.MetadataTSDBLabelMemoryBytes: "1000"}},
		{ID: "tsdb-large", Type: model.ResourceTypeTSDB, Name: "large", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataTSDBHeadSeries: "2000000", model.MetadataTSDBLabelMemoryBytes: "200000000"}},
		{ID: "tsdb-old", Type: model.ResourceTypeTSDB, Name: "old", Status: model.ResourceStatusDeprecated, Metadata: map[string]string{model.MetadataTSDBHeadSeries: "9000000", model.MetadataTSDBLabelMemoryBytes: "900000000"}},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	seriesFindings, err := NewHighSeriesTSDBAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(seriesFindings) != 1 || seriesFindings[0].Resource.ID != "tsdb-large" {
		t.Fatalf("expected high-series TSDB finding, findings=%#v err=%v", seriesFindings, err)
	}
	memoryFindings, err := NewHighTSDBLabelMemoryAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(memoryFindings) != 1 || memoryFindings[0].Resource.ID != "tsdb-large" {
		t.Fatalf("expected high-label-memory TSDB finding, findings=%#v err=%v", memoryFindings, err)
	}
}

func TestTSDBCostAnalyzersCustomThresholds(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := model.Resource{ID: "tsdb-test", Type: model.ResourceTypeTSDB, Name: "test", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataTSDBHeadSeries: "200", model.MetadataTSDBLabelMemoryBytes: "400"}}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	seriesFindings, err := NewHighSeriesTSDBAnalyzer().Execute(ctx, Context{Resources: store.Resources, Config: map[string]any{"tsdb_head_series_threshold": 100}})
	if err != nil || len(seriesFindings) != 1 {
		t.Fatalf("expected custom series threshold finding, findings=%#v err=%v", seriesFindings, err)
	}
	memoryFindings, err := NewHighTSDBLabelMemoryAnalyzer().Execute(ctx, Context{Resources: store.Resources, Config: map[string]any{"tsdb_label_memory_bytes_threshold": 300}})
	if err != nil || len(memoryFindings) != 1 {
		t.Fatalf("expected custom memory threshold finding, findings=%#v err=%v", memoryFindings, err)
	}
}
