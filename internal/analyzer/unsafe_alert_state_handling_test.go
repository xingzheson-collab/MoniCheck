package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestUnsafeAlertStateHandlingAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	safeRule := model.Resource{
		ID:     "alert-safe",
		Type:   model.ResourceTypeAlertRule,
		Name:   "SafeRule",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataNoDataState:  "Alerting",
			model.MetadataExecErrState: "Error",
		},
	}
	unsafeRule := model.Resource{
		ID:     "alert-unsafe",
		Type:   model.ResourceTypeAlertRule,
		Name:   "UnsafeRule",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataNoDataState:  "OK",
			model.MetadataExecErrState: "KeepLastState",
		},
	}
	disabledRule := model.Resource{
		ID:       "alert-disabled",
		Type:     model.ResourceTypeAlertRule,
		Name:     "DisabledRule",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataNoDataState: "OK", model.MetadataEnabled: "false"},
	}
	for _, resource := range []model.Resource{safeRule, unsafeRule, disabledRule} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewUnsafeAlertStateHandlingAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "UnsafeAlertStateHandling" || findings[0].Resource.ID != unsafeRule.ID {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if len(findings[0].Evidence) != 2 {
		t.Fatalf("expected two evidence items, got %#v", findings[0].Evidence)
	}
}
