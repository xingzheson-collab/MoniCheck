package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDisabledAlertAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	activeAlert := model.Resource{
		ID:     "alert-active",
		Type:   model.ResourceTypeAlertRule,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataEnabled: "true",
		},
	}
	disabledAlert := model.Resource{
		ID:     "alert-disabled",
		Type:   model.ResourceTypeAlertRule,
		Name:   "LegacyAlert",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDisabled: "true",
		},
	}

	for _, resource := range []model.Resource{activeAlert, disabledAlert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewDisabledAlertAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != disabledAlert.ID {
		t.Fatalf("expected disabled alert finding for %s, got %s", disabledAlert.ID, findings[0].Resource.ID)
	}
}
