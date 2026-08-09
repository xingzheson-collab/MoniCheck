package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDuplicateRuleAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	original := model.Resource{
		ID:     "alert-a",
		Type:   model.ResourceTypeAlertRule,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total{status=~\"5..\"}[5m])) > 10",
		},
	}
	duplicate := model.Resource{
		ID:     "alert-b",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DuplicateAPIHighErrorRate",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total{status=~\"5..\"}[5m]))   >   10",
		},
	}
	unique := model.Resource{
		ID:     "recording-a",
		Type:   model.ResourceTypeRecordingRule,
		Name:   "job:http_requests:rate5m",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total[5m])) by (job)",
		},
	}
	deprecatedDuplicate := model.Resource{
		ID:     "alert-deprecated",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DeprecatedDuplicateAPIHighErrorRate",
		Status: model.ResourceStatusDeprecated,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total{status=~\"5..\"}[5m])) > 10",
		},
	}
	disabledDuplicate := model.Resource{
		ID:     "alert-disabled",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DisabledDuplicateAPIHighErrorRate",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL:   "sum(rate(http_requests_total{status=~\"5..\"}[5m])) > 10",
			model.MetadataDisabled: "true",
		},
	}

	for _, resource := range []model.Resource{original, duplicate, unique, deprecatedDuplicate, disabledDuplicate} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewDuplicateRuleAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != duplicate.ID {
		t.Fatalf("expected duplicate rule finding for %s, got %s", duplicate.ID, findings[0].Resource.ID)
	}
	if findings[0].Metadata["duplicate_of_id"] != original.ID {
		t.Fatalf("expected duplicate_of_id %s, got %s", original.ID, findings[0].Metadata["duplicate_of_id"])
	}
}
