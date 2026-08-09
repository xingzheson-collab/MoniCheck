package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusAlertStateRestorationAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	healthy := prometheusAlertRestorationTestResource("healthy", "false", "3600", "600", "0")
	shortOutage := prometheusAlertRestorationTestResource("short-outage", "false", "1800", "600", "0")
	belowGrace := prometheusAlertRestorationTestResource("below-grace", "false", "3600", "600", "2")
	agent := prometheusAlertRestorationTestResource("agent", "true", "1800", "600", "2")
	flagsUnavailable := prometheusAlertRestorationTestResource("flags-unavailable", "false", "1800", "600", "2")
	flagsUnavailable.Metadata[model.MetadataPrometheusFlagsAvailable] = "false"
	rulesUnavailable := prometheusAlertRestorationTestResource("rules-unavailable", "false", "1800", "600", "2")
	rulesUnavailable.Metadata[model.MetadataRulesDiscoveryAvailable] = "false"
	noRules := prometheusAlertRestorationTestResource("no-rules", "false", "1800", "600", "2")
	noRules.Metadata[model.MetadataAlertingRuleCount] = "0"
	missing := prometheusAlertRestorationTestResource("missing", "false", "", "", "")
	delete(missing.Metadata, model.MetadataPrometheusAlertForOutageTolerance)
	delete(missing.Metadata, model.MetadataPrometheusAlertForGracePeriod)
	delete(missing.Metadata, model.MetadataPrometheusAlertForBelowGraceCount)
	wrongSource := prometheusAlertRestorationTestResource("wrong-source", "false", "1800", "600", "2")
	wrongSource.Source.System = "thanos"

	for _, resource := range []model.Resource{
		healthy, shortOutage, belowGrace, agent, flagsUnavailable,
		rulesUnavailable, noRules, missing, wrongSource,
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
		{NewPrometheusShortAlertOutageToleranceAnalyzer(), "short-outage", "PrometheusShortAlertOutageTolerance"},
		{NewPrometheusAlertForBelowGracePeriodAnalyzer(), "below-grace", "PrometheusAlertForBelowGracePeriod"},
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

func prometheusAlertRestorationTestResource(id, agentMode, outageTolerance, gracePeriod, belowGraceCount string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTSDB,
		Name:   "prometheus TSDB",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "test"},
		Metadata: map[string]string{
			model.MetadataPrometheusFlagsAvailable:          "true",
			model.MetadataRulesDiscoveryAvailable:           "true",
			model.MetadataPrometheusAgentMode:               agentMode,
			model.MetadataAlertingRuleCount:                 "3",
			model.MetadataPrometheusAlertForOutageTolerance: outageTolerance,
			model.MetadataPrometheusAlertForGracePeriod:     gracePeriod,
			model.MetadataPrometheusAlertForBelowGraceCount: belowGraceCount,
		},
	}
}
