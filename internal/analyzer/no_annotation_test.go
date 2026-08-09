package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestNoAnnotationAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	annotatedAlert := model.Resource{
		ID:     "alert-annotated",
		Type:   model.ResourceTypeAlertRule,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			"annotation.summary": "API has high 5xx rate",
		},
	}
	plainAlert := model.Resource{ID: "alert-plain", Type: model.ResourceTypeAlertRule, Name: "PlainAlert", Status: model.ResourceStatusActive}
	messageAlert := model.Resource{
		ID:     "alert-message",
		Type:   model.ResourceTypeAlertRule,
		Name:   "MessageAlert",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			"annotation.message": "API has high latency",
		},
	}
	disabledAlert := model.Resource{
		ID:     "alert-disabled",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DisabledAlert",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataEnabled: "false",
		},
	}

	for _, resource := range []model.Resource{annotatedAlert, plainAlert, messageAlert, disabledAlert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewNoAnnotationAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != plainAlert.ID {
		t.Fatalf("expected no annotation finding for %s, got %s", plainAlert.ID, findings[0].Resource.ID)
	}
}
