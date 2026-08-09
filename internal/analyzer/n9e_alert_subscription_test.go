package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBroadAlertSubscriptionAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	broad := n9eAlertSubscriptionForAnalyzer("broad", "all alerts", map[string]string{
		"subscription_rule_filter_count": "0", "subscription_tag_matcher_count": "0", "subscription_group_matcher_count": "0", "datasource_scope": "all",
	})
	scoped := n9eAlertSubscriptionForAnalyzer("scoped", "payments alerts", map[string]string{
		"subscription_rule_filter_count": "1", "subscription_tag_matcher_count": "0", "subscription_group_matcher_count": "0", "datasource_scope": "all",
	})
	for _, resource := range []model.Resource{broad, scoped} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	findings, err := NewBroadAlertSubscriptionAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != broad.ID {
		t.Fatalf("expected broad subscription finding only, got %#v", findings)
	}
}

func n9eAlertSubscriptionForAnalyzer(id string, name string, metadata map[string]string) model.Resource {
	metadata["policy_kind"] = "alert_subscription"
	metadata[model.MetadataEnabled] = "true"
	return model.Resource{ID: id, Type: model.ResourceTypeNotificationPolicy, Name: name, Status: model.ResourceStatusActive, Source: model.SourceInfo{System: "n9e"}, Metadata: metadata}
}
