package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestMissingSeverityLabelAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	withSeverity := model.Resource{
		ID:     "alert-severity",
		Type:   model.ResourceTypeAlertRule,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{"severity": "warning"},
	}
	withoutSeverity := model.Resource{
		ID:     "alert-no-severity",
		Type:   model.ResourceTypeAlertRule,
		Name:   "LegacyAlert",
		Status: model.ResourceStatusActive,
	}
	disabledRuleWithoutSeverity := model.Resource{
		ID:     "alert-disabled-no-severity",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DisabledLegacyAlert",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataEnabled: "false",
		},
	}
	alertWithoutSeverity := model.Resource{
		ID:     "runtime-alert-no-severity",
		Type:   model.ResourceTypeAlert,
		Name:   "RuntimeAlert",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
		},
	}
	suppressedAlertWithoutSeverity := model.Resource{
		ID:     "suppressed-alert-no-severity",
		Type:   model.ResourceTypeAlert,
		Name:   "SuppressedRuntimeAlert",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataAlertState: "suppressed",
		},
	}
	deprecatedActiveAlertWithoutSeverity := model.Resource{
		ID:     "deprecated-active-alert-no-severity",
		Type:   model.ResourceTypeAlert,
		Name:   "DeprecatedActiveRuntimeAlert",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
		},
	}
	for _, resource := range []model.Resource{withSeverity, withoutSeverity, disabledRuleWithoutSeverity, alertWithoutSeverity, suppressedAlertWithoutSeverity, deprecatedActiveAlertWithoutSeverity} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewMissingSeverityLabelAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
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
	if !found[withoutSeverity.ID] || !found[alertWithoutSeverity.ID] {
		t.Fatalf("expected findings for alert rule and active alert, got %#v", found)
	}
}
