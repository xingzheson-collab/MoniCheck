package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestDatadogGovernanceAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	noData := datadogMonitorTestResource("no-data")
	noData.Metadata[model.MetadataDatadogOverallState] = "No Data"
	unknown := datadogMonitorTestResource("unknown")
	unknown.Metadata[model.MetadataDatadogOverallState] = "Unknown"
	missingService := datadogMonitorTestResource("missing-service")
	missingService.Metadata[model.MetadataDatadogServiceTagDeclared] = "false"
	missingPriority := datadogMonitorTestResource("missing-priority")
	missingPriority.Metadata[model.MetadataDatadogPriorityDeclared] = "false"
	delete(missingPriority.Metadata, model.MetadataDatadogPriority)
	missingRunbook := datadogMonitorTestResource("missing-runbook")
	missingRunbook.Metadata[model.MetadataDatadogPriorityDeclared] = "true"
	missingRunbook.Metadata[model.MetadataDatadogPriority] = "1"
	missingRunbook.Metadata[model.MetadataDatadogRunbookConfigured] = "false"
	missingRenotify := datadogMonitorTestResource("missing-renotify")
	missingRenotify.Metadata[model.MetadataDatadogPriorityDeclared] = "true"
	missingRenotify.Metadata[model.MetadataDatadogPriority] = "2"
	missingRenotify.Metadata[model.MetadataDatadogRenotifyInterval] = "0"
	missingNoDataNotification := datadogMonitorTestResource("missing-no-data-notification")
	missingNoDataNotification.Metadata[model.MetadataDatadogPriorityDeclared] = "true"
	missingNoDataNotification.Metadata[model.MetadataDatadogPriority] = "1"
	missingNoDataNotification.Metadata[model.MetadataDatadogNoDataNotificationEvaluable] = "true"
	missingNoDataNotification.Metadata[model.MetadataDatadogNoDataNotificationConfigured] = "false"
	missingNotificationCoverage := datadogMonitorTestResource("missing-notification-coverage")
	missingNotificationCoverage.Metadata[model.MetadataDatadogPriorityDeclared] = "true"
	missingNotificationCoverage.Metadata[model.MetadataDatadogPriority] = "2"
	missingNotificationCoverage.Metadata[model.MetadataDatadogNotificationCoverageEvaluable] = "true"
	missingNotificationCoverage.Metadata[model.MetadataDatadogNotificationCoverageConfigured] = "false"
	missingRecoveryThreshold := datadogMonitorTestResource("missing-recovery-threshold")
	missingRecoveryThreshold.Metadata[model.MetadataDatadogPriorityDeclared] = "true"
	missingRecoveryThreshold.Metadata[model.MetadataDatadogPriority] = "1"
	missingRecoveryThreshold.Metadata[model.MetadataDatadogCriticalRecoveryEvaluable] = "true"
	missingRecoveryThreshold.Metadata[model.MetadataDatadogCriticalRecoveryConfigured] = "false"
	service := model.Resource{
		ID: "service", Type: model.ResourceTypeService, Name: "checkout",
		Source: model.SourceInfo{System: "datadog"}, Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatadogServiceDefinition: "true",
			model.MetadataDatadogTeamDeclared:      "false",
		},
	}
	for _, resource := range []model.Resource{noData, unknown, missingService, missingPriority, missingRunbook, missingRenotify, missingNoDataNotification, missingNotificationCoverage, missingRecoveryThreshold, service} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		analyzer Analyzer
		resource string
		typ      string
		severity model.Severity
		category model.FindingCategory
	}{
		{NewDatadogMonitorNoDataAnalyzer(), "no-data", "DatadogMonitorNoData", model.SeverityCritical, model.FindingCategoryReliability},
		{NewDatadogMonitorUnknownAnalyzer(), "unknown", "DatadogMonitorUnknown", model.SeverityWarning, model.FindingCategoryReliability},
		{NewDatadogMonitorWithoutServiceAnalyzer(), "missing-service", "DatadogMonitorWithoutService", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewDatadogMonitorWithoutPriorityAnalyzer(), "missing-priority", "DatadogMonitorWithoutPriority", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewDatadogMonitorWithoutRunbookAnalyzer(), "missing-runbook", "DatadogPriorityMonitorWithoutRunbook", model.SeverityWarning, model.FindingCategoryConfiguration},
		{NewDatadogMonitorWithoutRenotifyAnalyzer(), "missing-renotify", "DatadogPriorityMonitorWithoutRenotify", model.SeverityWarning, model.FindingCategoryReliability},
		{NewDatadogPriorityMonitorWithoutNoDataNotificationAnalyzer(), "missing-no-data-notification", "DatadogPriorityMonitorWithoutNoDataNotification", model.SeverityWarning, model.FindingCategoryReliability},
		{NewDatadogPriorityMonitorWithoutNotificationCoverageAnalyzer(), "missing-notification-coverage", "DatadogPriorityMonitorWithoutNotificationCoverage", model.SeverityWarning, model.FindingCategoryReliability},
		{NewDatadogPriorityMetricMonitorWithoutRecoveryAnalyzer(), "missing-recovery-threshold", "DatadogPriorityMetricMonitorWithoutRecoveryThreshold", model.SeverityWarning, model.FindingCategoryReliability},
		{NewDatadogServiceWithoutTeamAnalyzer(), "service", "DatadogServiceWithoutTeam", model.SeverityWarning, model.FindingCategoryLifecycle},
	}
	for _, test := range tests {
		findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil {
			t.Fatalf("%s: %v", test.analyzer.ID(), err)
		}
		if len(findings) != 1 || findings[0].Resource.ID != test.resource ||
			findings[0].Type != test.typ || findings[0].Severity != test.severity ||
			findings[0].Category != test.category {
			t.Fatalf("%s unexpected findings %#v", test.analyzer.ID(), findings)
		}
		if got := model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type); got != test.category {
			t.Fatalf("%s default category %s", test.analyzer.ID(), got)
		}
	}
}

func TestDatadogGovernanceAnalyzersSkipDraftAndOtherSystems(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	draft := datadogMonitorTestResource("draft")
	draft.Status = model.ResourceStatusDeprecated
	draft.Metadata[model.MetadataDatadogOverallState] = "No Data"
	other := datadogMonitorTestResource("other")
	other.Source.System = "grafana"
	other.Metadata[model.MetadataDatadogOverallState] = "No Data"
	for _, resource := range []model.Resource{draft, other} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatal(err)
		}
	}
	findings, err := NewDatadogMonitorNoDataAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
}

func TestDatadogPriorityMetricMonitorWithoutRecoveryAnalyzerGates(t *testing.T) {
	tests := []struct {
		name   string
		change func(*model.Resource)
	}{
		{
			name: "low priority",
			change: func(resource *model.Resource) {
				resource.Metadata[model.MetadataDatadogPriority] = "3"
			},
		},
		{
			name: "non metric monitor",
			change: func(resource *model.Resource) {
				resource.Metadata[model.MetadataDatadogMonitorType] = "service check"
			},
		},
		{
			name: "configured",
			change: func(resource *model.Resource) {
				resource.Metadata[model.MetadataDatadogCriticalRecoveryConfigured] = "true"
			},
		},
		{
			name: "unevaluable",
			change: func(resource *model.Resource) {
				resource.Metadata[model.MetadataDatadogCriticalRecoveryEvaluable] = "false"
			},
		},
	}
	analyzer := NewDatadogPriorityMetricMonitorWithoutRecoveryAnalyzer()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource := datadogMonitorTestResource(test.name)
			resource.Metadata[model.MetadataDatadogPriorityDeclared] = "true"
			resource.Metadata[model.MetadataDatadogPriority] = "1"
			resource.Metadata[model.MetadataDatadogCriticalRecoveryConfigured] = "false"
			test.change(&resource)
			if finding, ok := analyzer.finding(resource, time.Now().UTC()); ok {
				t.Fatalf("expected suppression, got %#v", finding)
			}
		})
	}
}

func datadogMonitorTestResource(id string) model.Resource {
	return model.Resource{
		ID: id, Type: model.ResourceTypeAlertRule, Name: id,
		Source: model.SourceInfo{System: "datadog"}, Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDatadogMonitor:                        "true",
			model.MetadataDatadogMonitorType:                    "metric alert",
			model.MetadataDatadogOverallState:                   "OK",
			model.MetadataDatadogServiceTagDeclared:             "true",
			model.MetadataDatadogPriorityDeclared:               "true",
			model.MetadataDatadogPriority:                       "3",
			model.MetadataDatadogRunbookConfigured:              "true",
			model.MetadataDatadogRenotifyInterval:               "30",
			model.MetadataDatadogNoDataNotificationEvaluable:    "true",
			model.MetadataDatadogNoDataNotificationConfigured:   "true",
			model.MetadataDatadogNotificationCoverageEvaluable:  "true",
			model.MetadataDatadogNotificationCoverageConfigured: "true",
			model.MetadataDatadogCriticalRecoveryEvaluable:      "true",
			model.MetadataDatadogCriticalRecoveryConfigured:     "true",
		},
	}
}
