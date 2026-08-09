package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusStorageCostAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	defaults := prometheusStorageCostTestResource("defaults", "1296000", "false", "false", "false")
	longRetention := prometheusStorageCostTestResource("long-retention", "2592000", "false", "false", "false")
	exemplar := prometheusStorageCostTestResource("exemplar", "1296000", "false", "true", "false")
	extraScrape := prometheusStorageCostTestResource("extra-scrape", "1296000", "true", "false", "true")
	agent := prometheusStorageCostTestResource("agent", "2592000", "true", "true", "false")
	flagsUnavailable := prometheusStorageCostTestResource("flags-unavailable", "1296000", "false", "true", "true")
	flagsUnavailable.Metadata[model.MetadataPrometheusFlagsAvailable] = "false"
	runtimeUnavailable := prometheusStorageCostTestResource("runtime-unavailable", "2592000", "false", "false", "false")
	runtimeUnavailable.Metadata[model.MetadataPrometheusRuntimeAvailable] = "false"
	wrongSource := prometheusStorageCostTestResource("wrong-source", "2592000", "false", "true", "true")
	wrongSource.Source.System = "thanos"
	inactive := prometheusStorageCostTestResource("inactive", "2592000", "false", "true", "true")
	inactive.Status = model.ResourceStatusDeprecated
	malformed := prometheusStorageCostTestResource("malformed", "long", "false", "false", "false")
	missing := prometheusStorageCostTestResource("missing", "", "", "", "")
	delete(missing.Metadata, model.MetadataPrometheusRetentionSeconds)
	delete(missing.Metadata, model.MetadataPrometheusAgentMode)
	delete(missing.Metadata, model.MetadataPrometheusExemplarStorageEnabled)
	delete(missing.Metadata, model.MetadataPrometheusExtraScrapeMetricsEnabled)

	for _, resource := range []model.Resource{
		defaults, longRetention, exemplar, extraScrape, agent, flagsUnavailable,
		runtimeUnavailable, wrongSource, inactive, malformed, missing,
	} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert TSDB resource: %v", err)
		}
	}

	tests := []struct {
		analyzer    Analyzer
		resourceID  string
		findingType string
		category    model.FindingCategory
	}{
		{NewPrometheusLongStorageRetentionAnalyzer(), "long-retention", "PrometheusLongStorageRetention", model.FindingCategoryCost},
		{NewPrometheusExemplarStorageEnabledAnalyzer(), "exemplar", "PrometheusExemplarStorageEnabled", model.FindingCategoryCost},
		{NewPrometheusDeprecatedExtraScrapeMetricsAnalyzer(), "extra-scrape", "PrometheusDeprecatedExtraScrapeMetrics", model.FindingCategoryLifecycle},
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
				findings[0].Category != test.category ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != test.category {
				t.Fatalf("unexpected findings: %#v", findings)
			}
		})
	}
}

func prometheusStorageCostTestResource(id, retention, agent, exemplar, extraScrape string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTSDB,
		Name:   "prometheus runtime",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "test"},
		Metadata: map[string]string{
			model.MetadataPrometheusRuntimeAvailable:          "true",
			model.MetadataPrometheusFlagsAvailable:            "true",
			model.MetadataPrometheusRetentionSeconds:          retention,
			model.MetadataPrometheusAgentMode:                 agent,
			model.MetadataPrometheusExemplarStorageEnabled:    exemplar,
			model.MetadataPrometheusExtraScrapeMetricsEnabled: extraScrape,
		},
	}
}
