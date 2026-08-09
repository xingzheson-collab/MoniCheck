package report

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBuildTrendFromSavedJSONExports(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	exports := []model.ReportExport{
		trendExport("governance-old", "governance", now.Add(-48*time.Hour), `{"generated_at":"2026-07-10T00:00:00Z","resource_count":10,"finding_count":5,"open_finding_count":4}`),
		trendExport("governance-new", "governance", now.Add(-24*time.Hour), `{"generated_at":"2026-07-11T00:00:00Z","resource_count":12,"finding_count":3,"open_finding_count":2}`),
		trendExport("cost-old", "cost", now.Add(-24*time.Hour), `{"generated_at":"2026-07-11T00:00:00Z","finding_count":5,"tsdb_head_series":1000,"tsdb_head_chunks":1200,"tsdb_label_memory_bytes":500000}`),
		trendExport("cost-new", "cost", now.Add(-12*time.Hour), `{"generated_at":"2026-07-11T12:00:00Z","finding_count":7,"critical_count":1,"warning_count":6,"tsdb_head_series":1400,"tsdb_head_chunks":1700,"tsdb_label_memory_bytes":650000}`),
		trendExport("governance-csv", "governance", now.Add(-6*time.Hour), "section,key,value\n"),
		trendExport("governance-stale", "governance", now.Add(-60*24*time.Hour), `{"resource_count":99,"finding_count":99}`),
	}
	exports[4].Format = "csv"
	for _, export := range exports {
		if err := store.ReportExports.Save(ctx, export); err != nil {
			t.Fatalf("save export: %v", err)
		}
	}

	trend, err := BuildTrend(ctx, store, []string{"governance,cost"}, 30)
	if err != nil {
		t.Fatalf("build trend: %v", err)
	}
	if trend.ExportCount != 4 || len(trend.Series) != 2 {
		t.Fatalf("expected 4 json exports across 2 series, got %#v", trend)
	}
	governance := trend.Series[1]
	if trend.Series[0].Type == "governance" {
		governance = trend.Series[0]
	}
	if governance.Type != "governance" || governance.PointCount != 2 {
		t.Fatalf("expected governance trend series, got %#v", governance)
	}
	if governance.Delta["resource_count"] != 2 || governance.Delta["finding_count"] != -2 || governance.Direction["finding_count"] != "down" {
		t.Fatalf("unexpected governance trend delta: %#v direction=%#v", governance.Delta, governance.Direction)
	}
	if governance.Latest == nil || governance.Latest.Metrics["open_finding_count"] != 2 {
		t.Fatalf("expected latest governance point, got %#v", governance.Latest)
	}
	cost := trend.Series[0]
	if cost.Type != "cost" {
		cost = trend.Series[1]
	}
	if cost.PointCount != 2 || cost.Delta["tsdb_head_series"] != 400 || cost.Delta["tsdb_head_chunks"] != 500 || cost.Delta["tsdb_label_memory_bytes"] != 150000 || cost.Direction["tsdb_head_series"] != "up" {
		t.Fatalf("unexpected TSDB cost trend: %#v", cost)
	}
}

func trendExport(id string, reportType string, createdAt time.Time, content string) model.ReportExport {
	return model.ReportExport{
		ID:          id,
		Type:        reportType,
		Format:      "json",
		Filename:    id + ".json",
		ContentType: "application/json",
		Content:     content,
		CreatedAt:   createdAt,
	}
}
