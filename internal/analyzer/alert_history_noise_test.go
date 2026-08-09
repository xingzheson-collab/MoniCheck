package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestAlertHistoryNoiseAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	noisy := model.Resource{ID: "noisy", Type: model.ResourceTypeAlertRule, Name: "NoisyAPI", Status: model.ResourceStatusActive, Metadata: map[string]string{
		"history_observed": "true", "history_window_hours": "24", "history_event_count": "30", "history_recovered_count": "12", "history_unrecovered_count": "18", "history_short_lived_count": "8", "history_notification_count": "90", "history_average_duration_seconds": "7200", "history_max_duration_seconds": "14400", "history_recovery_notification_observed_count": "12", "history_recovery_notification_disabled_count": "12", "history_recovery_notification_all_disabled": "true", "history_severity_variant_count": "2", "history_notification_route_observed_count": "20", "history_notification_route_variant_count": "3", "history_events_truncated": "true",
	}}
	stable := model.Resource{ID: "stable", Type: model.ResourceTypeAlertRule, Name: "StableAPI", Status: model.ResourceStatusActive, Metadata: map[string]string{
		"history_window_hours": "24", "history_event_count": "4", "history_recovered_count": "4", "history_short_lived_count": "1",
	}}
	dormant := model.Resource{ID: "dormant", Type: model.ResourceTypeAlertRule, Name: "DormantAPI", Status: model.ResourceStatusActive, Metadata: map[string]string{
		"history_observed": "true", "history_window_hours": "24", "history_event_count": "0", "history_events_truncated": "false",
	}}
	for _, resource := range []model.Resource{noisy, stable, dormant} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}
	analysis := Context{Resources: store.Resources, Graph: resourceGraph}
	noisyFindings, err := NewNoisyAlertRuleAnalyzer().Execute(ctx, analysis)
	if err != nil || len(noisyFindings) != 1 || noisyFindings[0].Resource.ID != noisy.ID || noisyFindings[0].Metadata["sampled"] != "true" {
		t.Fatalf("expected sampled noisy alert finding, got findings=%#v err=%v", noisyFindings, err)
	}
	flappingFindings, err := NewFlappingAlertRuleAnalyzer().Execute(ctx, analysis)
	if err != nil || len(flappingFindings) != 1 || flappingFindings[0].Resource.ID != noisy.ID {
		t.Fatalf("expected flapping alert finding, got findings=%#v err=%v", flappingFindings, err)
	}
	poorRecoveryFindings, err := NewPoorAlertRecoveryAnalyzer().Execute(ctx, analysis)
	if err != nil || len(poorRecoveryFindings) != 1 || poorRecoveryFindings[0].Resource.ID != noisy.ID || poorRecoveryFindings[0].Severity != model.SeverityCritical {
		t.Fatalf("expected poor alert recovery finding, got findings=%#v err=%v", poorRecoveryFindings, err)
	}
	stormFindings, err := NewAlertNotificationStormAnalyzer().Execute(ctx, analysis)
	if err != nil || len(stormFindings) != 1 || stormFindings[0].Resource.ID != noisy.ID || stormFindings[0].Metadata["notifications_per_event"] != "3.0000" {
		t.Fatalf("expected alert notification storm finding, got findings=%#v err=%v", stormFindings, err)
	}
	dormantFindings, err := NewDormantAlertRuleAnalyzer().Execute(ctx, analysis)
	if err != nil || len(dormantFindings) != 1 || dormantFindings[0].Resource.ID != dormant.ID || dormantFindings[0].Metadata["minimum_window_hours"] != "24" {
		t.Fatalf("expected dormant alert finding, got findings=%#v err=%v", dormantFindings, err)
	}
	slowRecoveryFindings, err := NewSlowAlertRecoveryAnalyzer().Execute(ctx, analysis)
	if err != nil || len(slowRecoveryFindings) != 1 || slowRecoveryFindings[0].Resource.ID != noisy.ID || slowRecoveryFindings[0].Metadata["threshold_seconds"] != "3600" || slowRecoveryFindings[0].Metadata["sampled"] != "true" {
		t.Fatalf("expected sampled slow recovery finding, got findings=%#v err=%v", slowRecoveryFindings, err)
	}
	recoveryNotificationFindings, err := NewRecoveryNotificationDisabledAnalyzer().Execute(ctx, analysis)
	if err != nil || len(recoveryNotificationFindings) != 1 || recoveryNotificationFindings[0].Resource.ID != noisy.ID || recoveryNotificationFindings[0].Metadata["sampled"] != "true" {
		t.Fatalf("expected sampled recovery notification finding, got findings=%#v err=%v", recoveryNotificationFindings, err)
	}
	severityDriftFindings, err := NewAlertSeverityDriftAnalyzer().Execute(ctx, analysis)
	if err != nil || len(severityDriftFindings) != 1 || severityDriftFindings[0].Resource.ID != noisy.ID || severityDriftFindings[0].Category != model.FindingCategoryConfiguration || severityDriftFindings[0].Metadata["sampled"] != "true" {
		t.Fatalf("expected sampled severity drift finding, got findings=%#v err=%v", severityDriftFindings, err)
	}
	routingDriftFindings, err := NewAlertRoutingDriftAnalyzer().Execute(ctx, analysis)
	if err != nil || len(routingDriftFindings) != 1 || routingDriftFindings[0].Resource.ID != noisy.ID || routingDriftFindings[0].Category != model.FindingCategoryConfiguration || routingDriftFindings[0].Metadata["route_variant_count"] != "3" {
		t.Fatalf("expected routing drift finding, got findings=%#v err=%v", routingDriftFindings, err)
	}
}

func TestDormantAlertRuleAnalyzerRequiresCompleteObservedWindow(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{ID: "short", Type: model.ResourceTypeAlertRule, Name: "Short", Status: model.ResourceStatusActive, Metadata: map[string]string{"history_observed": "true", "history_window_hours": "12", "history_event_count": "0"}},
		{ID: "truncated", Type: model.ResourceTypeAlertRule, Name: "Truncated", Status: model.ResourceStatusActive, Metadata: map[string]string{"history_observed": "true", "history_window_hours": "48", "history_event_count": "0", "history_events_truncated": "true"}},
		{ID: "unobserved", Type: model.ResourceTypeAlertRule, Name: "Unobserved", Status: model.ResourceStatusActive, Metadata: map[string]string{"history_window_hours": "48", "history_event_count": "0"}},
		{ID: "disabled", Type: model.ResourceTypeAlertRule, Name: "Disabled", Status: model.ResourceStatusActive, Metadata: map[string]string{"disabled": "true", "history_observed": "true", "history_window_hours": "48", "history_event_count": "0"}},
		{ID: "custom", Type: model.ResourceTypeAlertRule, Name: "CustomWindow", Status: model.ResourceStatusActive, Metadata: map[string]string{"history_observed": "true", "history_window_hours": "48", "history_event_count": "0"}},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewDormantAlertRuleAnalyzer().Execute(ctx, Context{Resources: store.Resources, Config: map[string]any{"dormant_alert_minimum_window_hours": 48}})
	if err != nil || len(findings) != 1 || findings[0].Resource.ID != "custom" {
		t.Fatalf("expected only complete custom-window rule, got findings=%#v err=%v", findings, err)
	}
}

func TestAlertHistoryNoiseAnalyzerThresholds(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	rule := model.Resource{ID: "custom", Type: model.ResourceTypeAlertRule, Name: "Custom", Status: model.ResourceStatusActive, Metadata: map[string]string{
		"history_observed": "true", "history_window_hours": "24", "history_event_count": "8", "history_recovered_count": "4", "history_unrecovered_count": "4", "history_short_lived_count": "3", "history_notification_count": "24", "history_average_duration_seconds": "1800", "history_max_duration_seconds": "3600", "history_recovery_notification_observed_count": "4", "history_recovery_notification_disabled_count": "4", "history_recovery_notification_all_disabled": "true",
	}}
	if err := store.Resources.Upsert(ctx, rule); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}
	resourceGraph, _ := graph.Build(ctx, store.Resources, store.Relationships)
	analysis := Context{Resources: store.Resources, Graph: resourceGraph, Config: map[string]any{
		"noisy_alert_event_threshold": 5, "flapping_alert_short_lived_threshold": 3, "flapping_alert_short_lived_ratio_threshold": 0.3,
		"poor_alert_recovery_event_threshold": 5, "poor_alert_recovery_ratio_threshold": 0.4,
		"alert_notification_storm_threshold": 20, "alert_notifications_per_event_threshold": 2.5,
		"slow_alert_recovery_threshold": "30m", "slow_alert_recovery_minimum_events": 4,
		"recovery_notification_minimum_events": 4,
	}}
	if findings, err := NewNoisyAlertRuleAnalyzer().Execute(ctx, analysis); err != nil || len(findings) != 1 {
		t.Fatalf("expected custom noisy threshold finding, got %#v err=%v", findings, err)
	}
	if findings, err := NewFlappingAlertRuleAnalyzer().Execute(ctx, analysis); err != nil || len(findings) != 1 {
		t.Fatalf("expected custom flapping threshold finding, got %#v err=%v", findings, err)
	}
	if findings, err := NewPoorAlertRecoveryAnalyzer().Execute(ctx, analysis); err != nil || len(findings) != 1 {
		t.Fatalf("expected custom poor recovery threshold finding, got %#v err=%v", findings, err)
	}
	if findings, err := NewAlertNotificationStormAnalyzer().Execute(ctx, analysis); err != nil || len(findings) != 1 {
		t.Fatalf("expected custom notification storm threshold finding, got %#v err=%v", findings, err)
	}
	if findings, err := NewSlowAlertRecoveryAnalyzer().Execute(ctx, analysis); err != nil || len(findings) != 1 {
		t.Fatalf("expected custom slow recovery threshold finding, got %#v err=%v", findings, err)
	}
	if findings, err := NewRecoveryNotificationDisabledAnalyzer().Execute(ctx, analysis); err != nil || len(findings) != 1 {
		t.Fatalf("expected custom recovery notification minimum finding, got %#v err=%v", findings, err)
	}
}

func TestRecoveryNotificationAnalyzerRequiresExplicitUniformHistory(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{ID: "missing", Type: model.ResourceTypeAlertRule, Name: "MissingField", Status: model.ResourceStatusActive, Metadata: map[string]string{"history_observed": "true", "history_recovered_count": "10"}},
		{ID: "small", Type: model.ResourceTypeAlertRule, Name: "SmallSample", Status: model.ResourceStatusActive, Metadata: map[string]string{"history_observed": "true", "history_recovery_notification_observed_count": "2", "history_recovery_notification_disabled_count": "2"}},
		{ID: "mixed", Type: model.ResourceTypeAlertRule, Name: "Mixed", Status: model.ResourceStatusActive, Metadata: map[string]string{"history_observed": "true", "history_recovery_notification_observed_count": "5", "history_recovery_notification_disabled_count": "4"}},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewRecoveryNotificationDisabledAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected missing, small, and mixed histories to be skipped, got %#v err=%v", findings, err)
	}
}

func TestAlertSeverityDriftRequiresObservedVariants(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{ID: "single", Type: model.ResourceTypeAlertRule, Name: "Single", Status: model.ResourceStatusActive, Metadata: map[string]string{"history_observed": "true", "history_event_count": "5", "history_severity_variant_count": "1"}},
		{ID: "unobserved", Type: model.ResourceTypeAlertRule, Name: "Unobserved", Status: model.ResourceStatusActive, Metadata: map[string]string{"history_event_count": "5", "history_severity_variant_count": "2"}},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewAlertSeverityDriftAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected single and unobserved severity histories to be skipped, got %#v err=%v", findings, err)
	}
}

func TestAlertRoutingDriftRequiresExplicitMultipleSets(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{ID: "single", Type: model.ResourceTypeAlertRule, Name: "Single", Status: model.ResourceStatusActive, Metadata: map[string]string{"history_observed": "true", "history_notification_route_observed_count": "5", "history_notification_route_variant_count": "1"}},
		{ID: "small", Type: model.ResourceTypeAlertRule, Name: "Small", Status: model.ResourceStatusActive, Metadata: map[string]string{"history_observed": "true", "history_notification_route_observed_count": "1", "history_notification_route_variant_count": "2"}},
		{ID: "missing", Type: model.ResourceTypeAlertRule, Name: "Missing", Status: model.ResourceStatusActive, Metadata: map[string]string{"history_observed": "true"}},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	findings, err := NewAlertRoutingDriftAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil || len(findings) != 0 {
		t.Fatalf("expected single, small, and missing route histories to be skipped, got %#v err=%v", findings, err)
	}
}
