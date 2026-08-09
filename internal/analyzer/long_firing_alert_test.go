package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestLongFiringAlertAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	freshAlert := model.Resource{
		ID:     "alert-fresh",
		Type:   model.ResourceTypeAlert,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
			model.MetadataStartsAt:   time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		},
	}
	longAlert := model.Resource{
		ID:     "alert-long",
		Type:   model.ResourceTypeAlert,
		Name:   "NodeDiskAlmostFull",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
			model.MetadataStartsAt:   time.Now().UTC().Add(-defaultLongFiringAlertThreshold - time.Hour).Format(time.RFC3339),
		},
	}

	for _, resource := range []model.Resource{freshAlert, longAlert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewLongFiringAlertAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != longAlert.ID {
		t.Fatalf("expected long firing alert finding for %s, got %s", longAlert.ID, findings[0].Resource.ID)
	}
}
