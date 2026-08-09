package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestNoActiveAlertInstanceAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	activeRule := model.Resource{ID: "rule-active", Type: model.ResourceTypeAlertRule, Name: "APIHighErrorRate", Status: model.ResourceStatusActive}
	inactiveRule := model.Resource{ID: "rule-inactive", Type: model.ResourceTypeAlertRule, Name: "LegacyAlert", Status: model.ResourceStatusActive}
	disabledRule := model.Resource{
		ID:       "rule-disabled",
		Type:     model.ResourceTypeAlertRule,
		Name:     "DisabledAlert",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataDisabled: "true"},
	}
	alert := model.Resource{
		ID:     "alert-active",
		Type:   model.ResourceTypeAlert,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataAlertState: "firing",
		},
	}
	for _, resource := range []model.Resource{activeRule, inactiveRule, disabledRule, alert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	if err := store.Relationships.Upsert(ctx, model.Relationship{
		ID:     "alert-rule",
		FromID: alert.ID,
		ToID:   activeRule.ID,
		Type:   model.RelationshipReferences,
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewNoActiveAlertInstanceAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != inactiveRule.ID {
		t.Fatalf("expected finding for %s, got %s", inactiveRule.ID, findings[0].Resource.ID)
	}
}
