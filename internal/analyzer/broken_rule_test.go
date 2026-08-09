package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBrokenRuleAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	healthyRule := model.Resource{
		ID:     "alert-healthy",
		Type:   model.ResourceTypeAlertRule,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataHealth: "ok",
		},
	}
	brokenRule := model.Resource{
		ID:     "recording-broken",
		Type:   model.ResourceTypeRecordingRule,
		Name:   "job:http_requests:rate5m",
		Status: model.ResourceStatusBroken,
		Metadata: map[string]string{
			model.MetadataHealth: "err",
		},
	}
	deprecatedBrokenRule := model.Resource{
		ID:     "recording-deprecated-broken",
		Type:   model.ResourceTypeRecordingRule,
		Name:   "DeprecatedBrokenRule",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataHealth: "err",
		},
	}
	disabledBrokenAlertRule := model.Resource{
		ID:     "alert-disabled-broken",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DisabledBrokenAlertRule",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataHealth:   "err",
			model.MetadataDisabled: "true",
		},
	}

	for _, resource := range []model.Resource{healthyRule, brokenRule, deprecatedBrokenRule, disabledBrokenAlertRule} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewBrokenRuleAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != brokenRule.ID {
		t.Fatalf("expected broken rule finding for %s, got %s", brokenRule.ID, findings[0].Resource.ID)
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", findings[0].Severity)
	}
}
