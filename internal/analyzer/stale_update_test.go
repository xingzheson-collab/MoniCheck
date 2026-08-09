package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestStaleUpdateAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()

	freshDashboard := model.Resource{
		ID:     "dashboard-fresh",
		Type:   model.ResourceTypeDashboard,
		Name:   "Fresh Dashboard",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataUpdatedAt: now.Add(-time.Hour).Format(time.RFC3339),
		},
	}
	staleRule := model.Resource{
		ID:     "rule-stale",
		Type:   model.ResourceTypeAlertRule,
		Name:   "LegacyAlert",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataUpdatedAt: now.Add(-defaultStaleUpdateThreshold - time.Hour).Format(time.RFC3339),
		},
	}
	deprecatedDashboard := model.Resource{
		ID:     "dashboard-deprecated",
		Type:   model.ResourceTypeDashboard,
		Name:   "Deprecated Dashboard",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataUpdatedAt: now.Add(-defaultStaleUpdateThreshold - time.Hour).Format(time.RFC3339),
		},
	}
	metricWithOldUpdate := model.Resource{
		ID:     "metric-old-update",
		Type:   model.ResourceTypeMetric,
		Name:   "metric_old_update_total",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataUpdatedAt: now.Add(-defaultStaleUpdateThreshold - time.Hour).Format(time.RFC3339),
		},
	}

	for _, resource := range []model.Resource{freshDashboard, staleRule, deprecatedDashboard, metricWithOldUpdate} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewStaleUpdateAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Type != "StaleUpdate" || finding.Resource.ID != staleRule.ID {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.Metadata["updated_at"] == "" || finding.Metadata["age"] == "" {
		t.Fatalf("expected updated_at and age metadata, got %#v", finding.Metadata)
	}
}

func TestStaleUpdateAnalyzerCustomThreshold(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	datasource := model.Resource{
		ID:     "datasource-stale",
		Type:   model.ResourceTypeDatasource,
		Name:   "Prometheus",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataUpdatedAt: time.Now().UTC().Add(-7 * 24 * time.Hour).Format(time.RFC3339),
		},
	}
	if err := store.Resources.Upsert(ctx, datasource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewStaleUpdateAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"stale_update_threshold": 24 * time.Hour},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != datasource.ID {
		t.Fatalf("expected finding for %s, got %#v", datasource.ID, findings)
	}
}
