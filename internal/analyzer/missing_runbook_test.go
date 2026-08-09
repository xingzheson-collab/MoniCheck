package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestMissingRunbookAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	missingRunbook := model.Resource{
		ID:     "alert-critical",
		Type:   model.ResourceTypeAlertRule,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{"severity": "critical"},
	}
	withAnnotationRunbook := model.Resource{
		ID:       "alert-warning",
		Type:     model.ResourceTypeAlertRule,
		Name:     "APILatencyHigh",
		Status:   model.ResourceStatusActive,
		Labels:   map[string]string{"severity": "warning"},
		Metadata: map[string]string{"annotation.runbook_url": "https://runbooks.example.com/api-latency"},
	}
	withN9ERunbook := model.Resource{
		ID:       "alert-n9e",
		Type:     model.ResourceTypeAlertRule,
		Name:     "DiskFullSoon",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{"severity": "warning", "runbook_url": "https://runbooks.example.com/disk"},
	}
	withNewRelicRunbook := model.Resource{
		ID:     "alert-newrelic",
		Type:   model.ResourceTypeAlertRule,
		Name:   "NewRelicAPIErrorRate",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{"severity": "critical"},
		Metadata: map[string]string{
			model.MetadataNewRelicRunbookConfigured: "true",
		},
	}
	infoRule := model.Resource{
		ID:     "alert-info",
		Type:   model.ResourceTypeAlertRule,
		Name:   "InfoOnly",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{"severity": "info"},
	}
	disabledRule := model.Resource{
		ID:       "alert-disabled",
		Type:     model.ResourceTypeAlertRule,
		Name:     "DisabledCritical",
		Status:   model.ResourceStatusActive,
		Labels:   map[string]string{"severity": "critical"},
		Metadata: map[string]string{model.MetadataDisabled: "true"},
	}
	runtimeAlertMissingRunbook := model.Resource{
		ID:     "runtime-alert-critical",
		Type:   model.ResourceTypeAlert,
		Name:   "RuntimeAPIHighErrorRate",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{"severity": "critical"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
		},
	}
	runtimeAlertWithRunbook := model.Resource{
		ID:     "runtime-alert-warning",
		Type:   model.ResourceTypeAlert,
		Name:   "RuntimeAPILatencyHigh",
		Status: model.ResourceStatusActive,
		Labels: map[string]string{"severity": "warning"},
		Metadata: map[string]string{
			model.MetadataAlertState: "firing",
			"annotation.runbook_url": "https://runbooks.example.com/runtime-api-latency",
		},
	}
	suppressedRuntimeAlert := model.Resource{
		ID:     "runtime-alert-suppressed",
		Type:   model.ResourceTypeAlert,
		Name:   "SuppressedRuntimeAlert",
		Status: model.ResourceStatusDeprecated,
		Labels: map[string]string{"severity": "critical"},
		Metadata: map[string]string{
			model.MetadataAlertState: "suppressed",
		},
	}
	deprecatedActiveRuntimeAlert := model.Resource{
		ID:     "runtime-alert-deprecated-active",
		Type:   model.ResourceTypeAlert,
		Name:   "DeprecatedActiveRuntimeAlert",
		Status: model.ResourceStatusDeprecated,
		Labels: map[string]string{"severity": "critical"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
		},
	}
	for _, resource := range []model.Resource{missingRunbook, withAnnotationRunbook, withN9ERunbook, withNewRelicRunbook, infoRule, disabledRule, runtimeAlertMissingRunbook, runtimeAlertWithRunbook, suppressedRuntimeAlert, deprecatedActiveRuntimeAlert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewMissingRunbookAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
		if finding.Type != "MissingRunbook" {
			t.Fatalf("expected MissingRunbook finding, got %s", finding.Type)
		}
	}
	if !found[missingRunbook.ID] || !found[runtimeAlertMissingRunbook.ID] {
		t.Fatalf("expected rule and runtime alert findings, got %#v", found)
	}
}
