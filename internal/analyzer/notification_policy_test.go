package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestNotificationPolicyAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		notificationPolicyResource("healthy", "alertmanager", "pagerduty", "5", "2", model.ResourceStatusActive),
		notificationPolicyResource("missing", "grafana", "", "3", "2", model.ResourceStatusActive),
		notificationPolicyResource("complex", "alertmanager", "default", "12", "6", model.ResourceStatusActive),
		notificationPolicyResource("deprecated", "grafana", "", "99", "9", model.ResourceStatusDeprecated),
		notificationPolicyResource("other", "custom", "", "99", "9", model.ResourceStatusActive),
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert policy: %v", err)
		}
	}

	missing, err := NewMissingDefaultReceiverAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(missing) != 1 || missing[0].Resource.ID != "missing" || missing[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected missing default receiver findings: %#v, %v", missing, err)
	}
	complex, err := NewComplexNotificationPolicyAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"notification_policy_route_count_threshold": 10, "notification_policy_depth_threshold": 5},
	})
	if err != nil || len(complex) != 1 || complex[0].Resource.ID != "complex" || complex[0].Metadata["route_count"] != "12" {
		t.Fatalf("unexpected complex policy findings: %#v, %v", complex, err)
	}
}

func TestNotificationPolicyRoutingRiskAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	shadowed := notificationPolicyResource("shadowed", "alertmanager", "default", "6", "3", model.ResourceStatusActive)
	shadowed.Metadata[model.MetadataPolicyShadowedRouteCount] = "3"
	fanout := notificationPolicyResource("fanout", "grafana", "default", "8", "3", model.ResourceStatusActive)
	fanout.Metadata[model.MetadataPolicyContinueRouteCount] = "2"
	fanout.Metadata[model.MetadataPolicyCatchAllContinueCount] = "1"
	healthy := notificationPolicyResource("healthy", "grafana", "default", "4", "2", model.ResourceStatusActive)
	healthy.Metadata[model.MetadataPolicyContinueRouteCount] = "1"
	for _, resource := range []model.Resource{shadowed, fanout, healthy} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert policy: %v", err)
		}
	}

	shadowFindings, err := NewShadowedNotificationRouteAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(shadowFindings) != 1 || shadowFindings[0].Resource.ID != shadowed.ID || shadowFindings[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected shadowed route findings: %#v, %v", shadowFindings, err)
	}
	fanoutFindings, err := NewNotificationFanoutRiskAnalyzer().Execute(ctx, Context{
		Resources: store.Resources, Config: map[string]any{"notification_policy_continue_route_threshold": 3},
	})
	if err != nil || len(fanoutFindings) != 1 || fanoutFindings[0].Resource.ID != fanout.ID || fanoutFindings[0].Severity != model.SeverityWarning {
		t.Fatalf("unexpected notification fanout findings: %#v, %v", fanoutFindings, err)
	}
}

func notificationPolicyResource(id, system, defaultReceiver, routeCount, maxDepth string, status model.ResourceStatus) model.Resource {
	return model.Resource{
		ID: id, Type: model.ResourceTypeNotificationPolicy, Name: "default", Status: status,
		Source: model.SourceInfo{System: system, Instance: "local", ExternalID: "notification-policy:default"},
		Metadata: map[string]string{
			model.MetadataPolicyDefaultReceiver: defaultReceiver,
			model.MetadataPolicyRouteCount:      routeCount,
			model.MetadataPolicyMaxDepth:        maxDepth,
		},
	}
}

func TestNotificationPolicyTimingAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	invalid := notificationPolicyResource("invalid-timing", "alertmanager", "default", "2", "2", model.ResourceStatusActive)
	invalid.Metadata[model.MetadataPolicyInvalidTimingCount] = "2"
	rounded := notificationPolicyResource("rounded-repeat", "grafana", "default", "3", "2", model.ResourceStatusActive)
	rounded.Metadata[model.MetadataPolicyRoundedRepeatCount] = "1"
	healthy := notificationPolicyResource("healthy-timing", "grafana", "default", "1", "1", model.ResourceStatusActive)
	ungrouped := notificationPolicyResource("ungrouped", "alertmanager", "default", "2", "2", model.ResourceStatusActive)
	ungrouped.Metadata[model.MetadataPolicyUngroupedRouteCount] = "1"
	for _, resource := range []model.Resource{invalid, rounded, healthy, ungrouped} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert timing policy: %v", err)
		}
	}
	invalidFindings, err := NewInvalidNotificationTimingAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(invalidFindings) != 1 || invalidFindings[0].Resource.ID != invalid.ID || invalidFindings[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected invalid timing findings: %#v, %v", invalidFindings, err)
	}
	roundedFindings, err := NewIneffectiveRepeatIntervalAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(roundedFindings) != 1 || roundedFindings[0].Resource.ID != rounded.ID || roundedFindings[0].Severity != model.SeverityWarning {
		t.Fatalf("unexpected rounded repeat findings: %#v, %v", roundedFindings, err)
	}
	ungroupedFindings, err := NewNotificationGroupingDisabledAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(ungroupedFindings) != 1 || ungroupedFindings[0].Resource.ID != ungrouped.ID || ungroupedFindings[0].Severity != model.SeverityWarning {
		t.Fatalf("unexpected grouping disabled findings: %#v, %v", ungroupedFindings, err)
	}
}
