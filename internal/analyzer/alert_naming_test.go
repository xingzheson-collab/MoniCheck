package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestAlertNamingAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	validAlert := model.Resource{ID: "alert-valid", Type: model.ResourceTypeAlertRule, Name: "APIHighErrorRate", Status: model.ResourceStatusActive}
	invalidAlert := model.Resource{ID: "alert-invalid", Type: model.ResourceTypeAlertRule, Name: "api_high_error_rate", Status: model.ResourceStatusActive}
	deprecatedInvalidAlert := model.Resource{ID: "alert-deprecated", Type: model.ResourceTypeAlertRule, Name: "deprecated_alert", Status: model.ResourceStatusDeprecated}
	disabledInvalidAlert := model.Resource{
		ID:     "alert-disabled",
		Type:   model.ResourceTypeAlertRule,
		Name:   "disabled_alert",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDisabled: "true",
		},
	}

	for _, resource := range []model.Resource{validAlert, invalidAlert, deprecatedInvalidAlert, disabledInvalidAlert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewAlertNamingAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != invalidAlert.ID {
		t.Fatalf("expected alert naming finding for %s, got %s", invalidAlert.ID, findings[0].Resource.ID)
	}
}
