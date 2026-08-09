package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestInvalidSeverityLabelAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	validRule := model.Resource{
		ID:     "alert-valid",
		Type:   model.ResourceTypeAlertRule,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{"severity": "warning"},
	}
	invalidRule := model.Resource{
		ID:     "alert-invalid",
		Type:   model.ResourceTypeAlertRule,
		Name:   "LegacyAlert",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{"severity": "urgent"},
	}
	disabledInvalidRule := model.Resource{
		ID:     "alert-disabled-invalid",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DisabledLegacyAlert",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{"severity": "urgent"},
		Metadata: map[string]string{
			model.MetadataEnabled: "false",
		},
	}
	missingRule := model.Resource{
		ID:     "alert-missing",
		Type:   model.ResourceTypeAlertRule,
		Name:   "MissingSeverity",
		Status: model.ResourceStatusActive,
	}
	invalidRuntimeAlert := model.Resource{
		ID:     "runtime-alert-invalid",
		Type:   model.ResourceTypeAlert,
		Name:   "RuntimeAlert",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{"severity": "urgent"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
		},
	}
	suppressedInvalidAlert := model.Resource{
		ID:     "runtime-alert-suppressed",
		Type:   model.ResourceTypeAlert,
		Name:   "SuppressedRuntimeAlert",
		Status: model.ResourceStatusDeprecated,
		Labels: map[string]string{"severity": "urgent"},
		Metadata: map[string]string{
			model.MetadataAlertState: "suppressed",
		},
	}
	deprecatedActiveInvalidAlert := model.Resource{
		ID:     "runtime-alert-deprecated-active",
		Type:   model.ResourceTypeAlert,
		Name:   "DeprecatedActiveRuntimeAlert",
		Status: model.ResourceStatusDeprecated,
		Labels: map[string]string{"severity": "urgent"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
		},
	}
	for _, resource := range []model.Resource{validRule, invalidRule, disabledInvalidRule, missingRule, invalidRuntimeAlert, suppressedInvalidAlert, deprecatedActiveInvalidAlert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewInvalidSeverityLabelAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
	}
	if !found[invalidRule.ID] || !found[invalidRuntimeAlert.ID] {
		t.Fatalf("expected findings for alert rule and active alert, got %#v", found)
	}
}

func TestInvalidSeverityLabelAnalyzerConfig(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	rule := model.Resource{
		ID:     "alert-custom",
		Type:   model.ResourceTypeAlertRule,
		Name:   "CustomSeverityAlert",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{"severity": "page"},
	}
	if err := store.Resources.Upsert(ctx, rule); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewInvalidSeverityLabelAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"allowed_severity_labels": "critical,warning,info,page"},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected custom severity to be allowed, got %d findings", len(findings))
	}
}
