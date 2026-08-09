package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestInvalidRunbookURLAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	validRule := model.Resource{
		ID:     "rule-valid",
		Type:   model.ResourceTypeAlertRule,
		Name:   "ValidRunbook",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			"runbook_url": "https://runbooks.example.com/api",
		},
	}
	relativeRule := model.Resource{
		ID:     "rule-relative",
		Type:   model.ResourceTypeAlertRule,
		Name:   "RelativeRunbook",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			"annotation.runbook_url": "/runbooks/api",
		},
	}
	unsupportedSchemeRule := model.Resource{
		ID:     "rule-unsupported-scheme",
		Type:   model.ResourceTypeAlertRule,
		Name:   "UnsupportedSchemeRunbook",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			"runbook": "file:///tmp/runbook.md",
		},
	}
	missingRule := model.Resource{
		ID:       "rule-missing",
		Type:     model.ResourceTypeAlertRule,
		Name:     "MissingRunbook",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{},
	}
	disabledRule := model.Resource{
		ID:     "rule-disabled",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DisabledRunbook",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDisabled: "true",
			"runbook_url":          "/runbooks/disabled",
		},
	}
	runtimeAlertInvalidRunbook := model.Resource{
		ID:     "runtime-alert-invalid-runbook",
		Type:   model.ResourceTypeAlert,
		Name:   "RuntimeInvalidRunbook",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
			"annotation.runbook_url": "/runtime/runbook",
		},
	}
	suppressedRuntimeAlertInvalidRunbook := model.Resource{
		ID:     "runtime-alert-suppressed-invalid-runbook",
		Type:   model.ResourceTypeAlert,
		Name:   "SuppressedRuntimeInvalidRunbook",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataAlertState: "suppressed",
			"annotation.runbook_url": "/runtime/suppressed",
		},
	}
	deprecatedActiveRuntimeAlertInvalidRunbook := model.Resource{
		ID:     "runtime-alert-deprecated-active-invalid-runbook",
		Type:   model.ResourceTypeAlert,
		Name:   "DeprecatedActiveRuntimeInvalidRunbook",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
			"annotation.runbook_url": "/runtime/deprecated-active",
		},
	}
	for _, resource := range []model.Resource{validRule, relativeRule, unsupportedSchemeRule, missingRule, disabledRule, runtimeAlertInvalidRunbook, suppressedRuntimeAlertInvalidRunbook, deprecatedActiveRuntimeAlertInvalidRunbook} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewInvalidRunbookURLAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
	found := map[string]bool{}
	for _, finding := range findings {
		found[finding.Resource.ID] = true
		if finding.Type != "InvalidRunbookURL" {
			t.Fatalf("expected InvalidRunbookURL, got %s", finding.Type)
		}
		if finding.Metadata["runbook_key"] == "" {
			t.Fatalf("expected runbook_key metadata, got %#v", finding.Metadata)
		}
	}
	if !found[relativeRule.ID] || !found[unsupportedSchemeRule.ID] || !found[runtimeAlertInvalidRunbook.ID] {
		t.Fatalf("expected relative, unsupported scheme, and runtime alert findings, got %#v", found)
	}
}
