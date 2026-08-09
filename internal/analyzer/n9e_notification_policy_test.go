package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestN9ENotificationPolicyAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	rule := model.Resource{ID: "rule-1", Type: model.ResourceTypeAlertRule, Name: "APIUnavailable", Status: model.ResourceStatusActive}
	undefined := n9eNotificationPolicy("policy-undefined", "notify-rule-999", true, "false")
	empty := n9eNotificationPolicy("policy-empty", "empty-policy", true, "true")
	configured := n9eNotificationPolicy("policy-configured", "configured-policy", true, "true")
	disabled := n9eNotificationPolicy("policy-disabled", "disabled-policy", false, "true")
	undefinedIndirect := n9eNotificationPolicy("policy-undefined-indirect", "notify-rule-998", true, "false")
	disabledIndirect := n9eNotificationPolicy("policy-disabled-indirect", "disabled-indirect", false, "true")
	subscription := n9eAlertSubscriptionForAnalyzer("subscription", "platform subscription", map[string]string{})
	receiver := model.Resource{ID: "receiver-1", Type: model.ResourceTypeReceiver, Name: "email", Status: model.ResourceStatusActive}
	for _, resource := range []model.Resource{rule, undefined, empty, configured, disabled, undefinedIndirect, disabledIndirect, subscription, receiver} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, relationship := range []model.Relationship{
		{ID: "rule-undefined", FromID: rule.ID, ToID: undefined.ID, Type: model.RelationshipUses, CreatedAt: now},
		{ID: "rule-disabled", FromID: rule.ID, ToID: disabled.ID, Type: model.RelationshipUses, CreatedAt: now},
		{ID: "configured-receiver", FromID: configured.ID, ToID: receiver.ID, Type: model.RelationshipUses, CreatedAt: now},
		{ID: "subscription-configured", FromID: subscription.ID, ToID: configured.ID, Type: model.RelationshipUses, CreatedAt: now},
		{ID: "subscription-undefined", FromID: subscription.ID, ToID: undefinedIndirect.ID, Type: model.RelationshipUses, CreatedAt: now},
		{ID: "subscription-disabled", FromID: subscription.ID, ToID: disabledIndirect.ID, Type: model.RelationshipUses, CreatedAt: now},
	} {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	analysis := Context{Resources: store.Resources, Graph: resourceGraph}

	undefinedFindings, err := NewUndefinedNotificationPolicyAnalyzer().Execute(ctx, analysis)
	if err != nil {
		t.Fatalf("execute undefined analyzer: %v", err)
	}
	if len(undefinedFindings) != 2 || !findingResourcesInclude(undefinedFindings, undefined.ID, undefinedIndirect.ID) {
		t.Fatalf("expected direct and subscription-referenced undefined policy findings, got %#v", undefinedFindings)
	}

	emptyFindings, err := NewNotificationPolicyWithoutReceiverAnalyzer().Execute(ctx, analysis)
	if err != nil {
		t.Fatalf("execute empty policy analyzer: %v", err)
	}
	if len(emptyFindings) != 1 || emptyFindings[0].Resource.ID != empty.ID {
		t.Fatalf("expected enabled empty policy finding only, got %#v", emptyFindings)
	}

	disabledFindings, err := NewDisabledNotificationPolicyAnalyzer().Execute(ctx, analysis)
	if err != nil {
		t.Fatalf("execute disabled policy analyzer: %v", err)
	}
	if len(disabledFindings) != 2 || !findingResourcesInclude(disabledFindings, disabled.ID, disabledIndirect.ID) {
		t.Fatalf("expected direct and subscription-referenced disabled policy findings, got %#v", disabledFindings)
	}
}

func findingResourcesInclude(findings []model.Finding, resourceIDs ...string) bool {
	want := make(map[string]bool, len(resourceIDs))
	for _, resourceID := range resourceIDs {
		want[resourceID] = true
	}
	for _, finding := range findings {
		delete(want, finding.Resource.ID)
	}
	return len(want) == 0
}

func n9eNotificationPolicy(id string, name string, enabled bool, declared string) model.Resource {
	status := model.ResourceStatusActive
	if !enabled {
		status = model.ResourceStatusDeprecated
	}
	return model.Resource{
		ID: id, Type: model.ResourceTypeNotificationPolicy, Name: name, Status: status,
		Source:   model.SourceInfo{System: "n9e", Instance: "local", ExternalID: id},
		Metadata: map[string]string{"declared": declared, model.MetadataEnabled: map[bool]string{true: "true", false: "false"}[enabled]},
	}
}
