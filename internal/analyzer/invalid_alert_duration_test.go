package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestInvalidAlertDurationAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	validRule := model.Resource{
		ID:     "rule-valid",
		Type:   model.ResourceTypeAlertRule,
		Name:   "ValidDuration",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataAlertFor: "5m",
		},
	}
	numericRule := model.Resource{
		ID:     "rule-numeric",
		Type:   model.ResourceTypeAlertRule,
		Name:   "NumericDuration",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataAlertFor: "300",
		},
	}
	missingRule := model.Resource{
		ID:       "rule-missing",
		Type:     model.ResourceTypeAlertRule,
		Name:     "MissingDuration",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{},
	}
	invalidRule := model.Resource{
		ID:     "rule-invalid",
		Type:   model.ResourceTypeAlertRule,
		Name:   "InvalidDuration",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			"hold_duration": "five minutes",
		},
	}
	zeroRule := model.Resource{
		ID:     "rule-zero",
		Type:   model.ResourceTypeAlertRule,
		Name:   "ZeroDuration",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataAlertFor: "0s",
		},
	}
	disabledRule := model.Resource{
		ID:     "rule-disabled",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DisabledDuration",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDisabled: "true",
			model.MetadataAlertFor: "bad",
		},
	}
	for _, resource := range []model.Resource{validRule, numericRule, missingRule, invalidRule, zeroRule, disabledRule} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewInvalidAlertDurationAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
		if finding.Type != "InvalidAlertDuration" {
			t.Fatalf("expected InvalidAlertDuration, got %s", finding.Type)
		}
		if finding.Metadata["duration_key"] == "" {
			t.Fatalf("expected duration_key metadata, got %#v", finding.Metadata)
		}
	}
	if !found[invalidRule.ID] || !found[zeroRule.ID] {
		t.Fatalf("expected invalid and zero duration findings, got %#v", found)
	}
}
