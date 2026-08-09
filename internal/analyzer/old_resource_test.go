package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOldResourceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()

	freshMetric := model.Resource{
		ID:        "metric-fresh",
		Type:      model.ResourceTypeMetric,
		Name:      "http_requests_total",
		Status:    model.ResourceStatusActive,
		CreatedAt: now.Add(-time.Hour),
	}
	oldDashboard := model.Resource{
		ID:        "dashboard-old",
		Type:      model.ResourceTypeDashboard,
		Name:      "Legacy Dashboard",
		Status:    model.ResourceStatusActive,
		CreatedAt: now.Add(-defaultOldResourceAgeThreshold - time.Hour),
	}
	oldDeprecatedDatasource := model.Resource{
		ID:        "datasource-deprecated",
		Type:      model.ResourceTypeDatasource,
		Name:      "Old Prometheus",
		Status:    model.ResourceStatusDeprecated,
		CreatedAt: now.Add(-defaultOldResourceAgeThreshold - time.Hour),
	}

	for _, resource := range []model.Resource{freshMetric, oldDashboard, oldDeprecatedDatasource} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewOldResourceAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Type != "OldResource" || finding.Resource.ID != oldDashboard.ID {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.Metadata["created_at"] == "" || finding.Metadata["age"] == "" {
		t.Fatalf("expected created_at and age metadata, got %#v", finding.Metadata)
	}
}

func TestOldResourceAnalyzerCustomThreshold(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	panel := model.Resource{
		ID:        "panel-week-old",
		Type:      model.ResourceTypePanel,
		Name:      "Week Old Panel",
		Status:    model.ResourceStatusActive,
		CreatedAt: time.Now().UTC().Add(-7 * 24 * time.Hour),
	}
	if err := store.Resources.Upsert(ctx, panel); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewOldResourceAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"old_resource_age_threshold": 24 * time.Hour},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != panel.ID {
		t.Fatalf("expected finding for %s, got %#v", panel.ID, findings)
	}
}
