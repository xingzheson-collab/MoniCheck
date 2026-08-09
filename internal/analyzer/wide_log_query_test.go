package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestWideLogQueryAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	normalPanel := model.Resource{
		ID:     "panel-log-normal",
		Type:   model.ResourceTypePanel,
		Name:   "Recent Errors",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataQuery:         `sum(count_over_time({app="api"} |= "error" [5m]))`,
			model.MetadataQueryLanguage: "logql",
		},
	}
	widePanel := model.Resource{
		ID:     "panel-log-wide",
		Type:   model.ResourceTypePanel,
		Name:   "Weekly Errors",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataQuery:         `sum(count_over_time({app="api"} |= "error" [7d]))`,
			model.MetadataQueryLanguage: "logql",
		},
	}
	promPanel := model.Resource{
		ID:     "panel-prom",
		Type:   model.ResourceTypePanel,
		Name:   "Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total[7d]))",
		},
	}
	for _, resource := range []model.Resource{normalPanel, widePanel, promPanel} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewWideLogQueryAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "WideLogQuery" || findings[0].Resource.ID != widePanel.ID || findings[0].Metadata["max_range"] != (7*24*time.Hour).String() {
		t.Fatalf("expected wide log query finding, got %#v", findings[0])
	}
}

func TestWideLogQueryAnalyzerConfiguredThreshold(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	panel := model.Resource{
		ID:     "panel-log",
		Type:   model.ResourceTypePanel,
		Name:   "Long Log Query",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataQuery:         `count_over_time({service="checkout"}[6h])`,
			model.MetadataQueryLanguage: "logql",
		},
	}
	if err := store.Resources.Upsert(ctx, panel); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewWideLogQueryAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config: map[string]any{
			"wide_log_query_threshold": 4 * time.Hour,
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected configured threshold finding, got %d", len(findings))
	}
}
