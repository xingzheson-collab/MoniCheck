package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestHighImpactAlertWithoutReceiverAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	rule := model.Resource{
		ID:     "rule-high-impact",
		Type:   model.ResourceTypeAlertRule,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
	}
	lowImpactRule := model.Resource{
		ID:     "rule-low-impact",
		Type:   model.ResourceTypeAlertRule,
		Name:   "WorkerLag",
		Status: model.ResourceStatusActive,
	}
	disabledRule := model.Resource{
		ID:     "rule-disabled",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DisabledRule",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDisabled: "true",
		},
	}
	alerts := []model.Resource{
		alertInstance("alert-1", "APIHighErrorRate pod=a", "firing", ""),
		alertInstance("alert-2", "APIHighErrorRate pod=b", "active", ""),
		alertInstance("alert-3", "APIHighErrorRate pod=c", "pending", "pagerduty"),
		alertInstance("alert-4", "APIHighErrorRate pod=d", "", "slack-platform"),
		alertInstance("alert-resolved", "APIHighErrorRate pod=old", "resolved", ""),
		alertInstance("alert-low", "WorkerLag pod=a", "firing", ""),
		alertInstance("alert-disabled", "DisabledRule pod=a", "firing", ""),
	}
	for _, resource := range append([]model.Resource{rule, lowImpactRule, disabledRule}, alerts...) {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	relationships := []model.Relationship{
		{ID: "alert-1-rule", FromID: "alert-1", ToID: rule.ID, Type: model.RelationshipReferences},
		{ID: "alert-1-rule-duplicate", FromID: "alert-1", ToID: rule.ID, Type: model.RelationshipReferences},
		{ID: "alert-2-rule", FromID: "alert-2", ToID: rule.ID, Type: model.RelationshipReferences},
		{ID: "alert-3-rule", FromID: "alert-3", ToID: rule.ID, Type: model.RelationshipReferences},
		{ID: "alert-4-rule", FromID: "alert-4", ToID: rule.ID, Type: model.RelationshipReferences},
		{ID: "alert-resolved-rule", FromID: "alert-resolved", ToID: rule.ID, Type: model.RelationshipReferences},
		{ID: "alert-low-rule", FromID: "alert-low", ToID: lowImpactRule.ID, Type: model.RelationshipReferences},
		{ID: "alert-disabled-rule", FromID: "alert-disabled", ToID: disabledRule.ID, Type: model.RelationshipReferences},
	}
	for _, relationship := range relationships {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewHighImpactAlertWithoutReceiverAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Graph:     resourceGraph,
		Config:    map[string]any{"high_impact_alert_instance_threshold": 3},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(findings), findings)
	}
	finding := findings[0]
	if finding.Type != "HighImpactAlertWithoutReceiver" || finding.Resource.ID != rule.ID {
		t.Fatalf("unexpected finding: %#v", finding)
	}
	if finding.Metadata["active_alert_instance_count"] != "4" {
		t.Fatalf("expected 4 active alert instances after filtering/dedup, got %#v", finding.Metadata)
	}
	if finding.Metadata["missing_receiver_instance_count"] != "2" {
		t.Fatalf("expected 2 missing receivers, got %#v", finding.Metadata)
	}
}

func alertInstance(id, name, state, receivers string) model.Resource {
	metadata := map[string]string{
		model.MetadataAlertState: state,
	}
	if receivers != "" {
		metadata[model.MetadataReceiverNames] = receivers
	}
	return model.Resource{
		ID:       id,
		Type:     model.ResourceTypeAlert,
		Name:     name,
		Status:   model.ResourceStatusActive,
		Metadata: metadata,
	}
}
