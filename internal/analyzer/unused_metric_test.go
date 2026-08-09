package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestUnusedMetricAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	usedMetric := model.Resource{
		ID:     "metric-used",
		Type:   model.ResourceTypeMetric,
		Name:   "http_requests_total",
		Status: model.ResourceStatusActive,
	}
	unusedMetric := model.Resource{
		ID:     "metric-unused",
		Type:   model.ResourceTypeMetric,
		Name:   "legacy_queue_depth",
		Status: model.ResourceStatusActive,
	}
	inactiveOnlyMetric := model.Resource{
		ID:     "metric-inactive-only",
		Type:   model.ResourceTypeMetric,
		Name:   "old_panel_metric",
		Status: model.ResourceStatusActive,
	}
	panel := model.Resource{
		ID:     "panel-1",
		Type:   model.ResourceTypePanel,
		Name:   "Request Rate",
		Status: model.ResourceStatusActive,
	}
	inactivePanel := model.Resource{
		ID:     "panel-old",
		Type:   model.ResourceTypePanel,
		Name:   "Old Panel",
		Status: model.ResourceStatusDeprecated,
	}
	target := model.Resource{
		ID:     "target-1",
		Type:   model.ResourceTypeTarget,
		Name:   "http://10.0.0.1:9100/metrics",
		Status: model.ResourceStatusActive,
	}

	for _, resource := range []model.Resource{usedMetric, unusedMetric, inactiveOnlyMetric, panel, inactivePanel, target} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, relationship := range []model.Relationship{
		{
			ID:     "rel-1",
			FromID: panel.ID,
			ToID:   usedMetric.ID,
			Type:   model.RelationshipUses,
		},
		{
			ID:     "rel-2",
			FromID: target.ID,
			ToID:   unusedMetric.ID,
			Type:   model.RelationshipProduces,
		},
		{
			ID:     "rel-3",
			FromID: inactivePanel.ID,
			ToID:   inactiveOnlyMetric.ID,
			Type:   model.RelationshipUses,
		},
	} {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewUnusedMetricAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(findings), findings)
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
		assertEnglishRecommendation(t, finding)
	}
	if !found[unusedMetric.ID] || !found[inactiveOnlyMetric.ID] {
		t.Fatalf("expected unused metric findings for %s and %s, got %#v", unusedMetric.ID, inactiveOnlyMetric.ID, findings)
	}
}

func TestUnusedMetricAnalyzerWithoutGraph(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	if err := store.Resources.Upsert(ctx, model.Resource{ID: "metric-unused", Type: model.ResourceTypeMetric, Name: "legacy_queue_depth", Status: model.ResourceStatusActive}); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewUnusedMetricAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings without graph, got %#v", findings)
	}
}
