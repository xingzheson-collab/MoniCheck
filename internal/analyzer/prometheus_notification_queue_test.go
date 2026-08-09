package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusNotificationQueueAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	zeroQueue := prometheusNotificationQueueTestResource("zero-queue", "2", "2", "0", "true")
	noDrain := prometheusNotificationQueueTestResource("no-drain", "2", "2", "10000", "false")
	healthy := prometheusNotificationQueueTestResource("healthy", "2", "2", "10000", "true")
	shortResend := prometheusNotificationQueueTestResource("short-resend", "2", "2", "10000", "true")
	shortResend.Metadata[model.MetadataPrometheusAlertResendDelay] = "15"
	largeBatch := prometheusNotificationQueueTestResource("large-batch", "2", "2", "10000", "true")
	largeBatch.Metadata[model.MetadataPrometheusNotificationBatchSize] = "1024"
	externalRules := prometheusNotificationQueueTestResource("external-rules", "0", "2", "0", "false")
	externalRules.Metadata[model.MetadataPrometheusAlertResendDelay] = "15"
	externalRules.Metadata[model.MetadataPrometheusNotificationBatchSize] = "1024"
	noActiveAlertmanager := prometheusNotificationQueueTestResource("no-active-alertmanager", "2", "0", "0", "false")
	noActiveAlertmanager.Metadata[model.MetadataPrometheusAlertResendDelay] = "15"
	noActiveAlertmanager.Metadata[model.MetadataPrometheusNotificationBatchSize] = "1024"
	agent := prometheusNotificationQueueTestResource("agent", "2", "2", "0", "false")
	agent.Metadata[model.MetadataPrometheusAgentMode] = "true"
	agent.Metadata[model.MetadataPrometheusAlertResendDelay] = "15"
	agent.Metadata[model.MetadataPrometheusNotificationBatchSize] = "1024"
	flagsUnavailable := prometheusNotificationQueueTestResource("flags-unavailable", "2", "2", "0", "false")
	flagsUnavailable.Metadata[model.MetadataPrometheusFlagsAvailable] = "false"
	flagsUnavailable.Metadata[model.MetadataPrometheusAlertResendDelay] = "15"
	flagsUnavailable.Metadata[model.MetadataPrometheusNotificationBatchSize] = "1024"
	rulesUnavailable := prometheusNotificationQueueTestResource("rules-unavailable", "2", "2", "0", "false")
	rulesUnavailable.Metadata[model.MetadataRulesDiscoveryAvailable] = "false"
	rulesUnavailable.Metadata[model.MetadataPrometheusAlertResendDelay] = "15"
	rulesUnavailable.Metadata[model.MetadataPrometheusNotificationBatchSize] = "1024"
	alertmanagersUnavailable := prometheusNotificationQueueTestResource("alertmanagers-unavailable", "2", "2", "0", "false")
	alertmanagersUnavailable.Metadata[model.MetadataPrometheusAMDiscoveryAvailable] = "false"
	alertmanagersUnavailable.Metadata[model.MetadataPrometheusAlertResendDelay] = "15"
	alertmanagersUnavailable.Metadata[model.MetadataPrometheusNotificationBatchSize] = "1024"
	missing := prometheusNotificationQueueTestResource("missing", "2", "2", "", "")
	delete(missing.Metadata, model.MetadataPrometheusNotificationQueueCapacity)
	delete(missing.Metadata, model.MetadataPrometheusDrainNotificationQueue)
	wrongSource := prometheusNotificationQueueTestResource("wrong-source", "2", "2", "0", "false")
	wrongSource.Source.System = "thanos"

	for _, resource := range []model.Resource{
		zeroQueue, noDrain, healthy, shortResend, largeBatch, externalRules, noActiveAlertmanager, agent,
		flagsUnavailable, rulesUnavailable, alertmanagersUnavailable, missing, wrongSource,
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert TSDB resource: %v", err)
		}
	}

	tests := []struct {
		analyzer    Analyzer
		resourceID  string
		findingType string
	}{
		{NewPrometheusZeroNotificationQueueCapacityAnalyzer(), "zero-queue", "PrometheusZeroNotificationQueueCapacity"},
		{NewPrometheusNotificationQueueNotDrainedAnalyzer(), "no-drain", "PrometheusNotificationQueueNotDrained"},
		{NewPrometheusShortAlertResendDelayAnalyzer(), "short-resend", "PrometheusShortAlertResendDelay"},
		{NewPrometheusLargeNotificationBatchSizeAnalyzer(), "large-batch", "PrometheusLargeNotificationBatchSize"},
	}
	for _, test := range tests {
		t.Run(test.analyzer.ID(), func(t *testing.T) {
			findings, err := test.analyzer.Execute(ctx, Context{Resources: store.Resources})
			if err != nil {
				t.Fatalf("execute analyzer: %v", err)
			}
			if len(findings) != 1 ||
				findings[0].Resource.ID != test.resourceID ||
				findings[0].Type != test.findingType ||
				findings[0].Severity != model.SeverityWarning ||
				findings[0].Category != model.FindingCategoryReliability ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
				t.Fatalf("unexpected findings: %#v", findings)
			}
		})
	}
}

func prometheusNotificationQueueTestResource(id, alertingRules, activeAlertmanagers, capacity, drain string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTSDB,
		Name:   "prometheus TSDB",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "test"},
		Metadata: map[string]string{
			model.MetadataRulesDiscoveryAvailable:             "true",
			model.MetadataAlertingRuleCount:                   alertingRules,
			model.MetadataPrometheusAMDiscoveryAvailable:      "true",
			model.MetadataPrometheusActiveAMCount:             activeAlertmanagers,
			model.MetadataPrometheusFlagsAvailable:            "true",
			model.MetadataPrometheusAgentMode:                 "false",
			model.MetadataPrometheusNotificationQueueCapacity: capacity,
			model.MetadataPrometheusDrainNotificationQueue:    drain,
			model.MetadataPrometheusAlertResendDelay:          "60",
			model.MetadataPrometheusNotificationBatchSize:     "256",
		},
	}
}
