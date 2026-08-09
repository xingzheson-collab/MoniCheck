package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOrphanAlertAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	usedAlert := model.Resource{ID: "alert-used", Type: model.ResourceTypeAlertRule, Name: "APIHighErrorRate", Status: model.ResourceStatusActive}
	orphanAlert := model.Resource{ID: "alert-orphan", Type: model.ResourceTypeAlertRule, Name: "LegacyAlert", Status: model.ResourceStatusActive}
	disabledAlert := model.Resource{
		ID:       "alert-disabled",
		Type:     model.ResourceTypeAlertRule,
		Name:     "DisabledAlert",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataDisabled: "true"},
	}
	deprecatedAlert := model.Resource{ID: "alert-deprecated", Type: model.ResourceTypeAlertRule, Name: "DeprecatedAlert", Status: model.ResourceStatusDeprecated}
	metric := model.Resource{ID: "metric-1", Type: model.ResourceTypeMetric, Name: "http_requests_total", Status: model.ResourceStatusActive}

	for _, resource := range []model.Resource{usedAlert, orphanAlert, disabledAlert, deprecatedAlert, metric} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID:     "alert-metric",
		FromID: usedAlert.ID,
		ToID:   metric.ID,
		Type:   model.RelationshipUses,
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewOrphanAlertAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != orphanAlert.ID {
		t.Fatalf("expected orphan alert finding for %s, got %s", orphanAlert.ID, findings[0].Resource.ID)
	}
}

func TestOrphanAlertAnalyzerWithoutGraph(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	if err := store.Resources.Upsert(ctx, model.Resource{ID: "alert-orphan", Type: model.ResourceTypeAlertRule, Name: "LegacyAlert", Status: model.ResourceStatusActive}); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewOrphanAlertAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings without graph, got %#v", findings)
	}
}
