package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestRiskyLogLabelAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	for _, resource := range []model.Resource{
		{ID: "label-app", Type: model.ResourceTypeLogLabel, Name: "app", Status: model.ResourceStatusActive},
		{ID: "label-user", Type: model.ResourceTypeLogLabel, Name: "user_id", Status: model.ResourceStatusActive},
		{ID: "label-request", Type: model.ResourceTypeLogLabel, Name: "request-id", Status: model.ResourceStatusActive},
		{ID: "label-deprecated-session", Type: model.ResourceTypeLogLabel, Name: "session_id", Status: model.ResourceStatusDeprecated},
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewRiskyLogLabelAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %#v", findings)
	}
	if findings[0].Resource.Name != "request-id" || findings[1].Resource.Name != "user_id" {
		t.Fatalf("expected sorted risky log label findings, got %#v", findings)
	}
	if findings[1].Metadata["normalized_label"] != "user_id" {
		t.Fatalf("expected normalized metadata, got %#v", findings[1].Metadata)
	}
}

func TestRiskyLogLabelAnalyzerCustomNames(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := model.Resource{
		ID:     "label-tenant",
		Type:   model.ResourceTypeLogLabel,
		Name:   "tenant.slug",
		Status: model.ResourceStatusActive,
	}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	findings, err := NewRiskyLogLabelAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"risky_log_label_names": []string{"tenant_slug"}},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != resource.ID {
		t.Fatalf("expected custom risky label finding, got %#v", findings)
	}
}
