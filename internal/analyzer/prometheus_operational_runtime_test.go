package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusOperationalRuntimeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	defaults := prometheusOperationalRuntimeTestResource("defaults", "info", "false", "30", "16")
	debug := prometheusOperationalRuntimeTestResource("debug", "debug", "false", "30", "16")
	longReload := prometheusOperationalRuntimeTestResource("long-reload", "info", "true", "120", "16")
	highSubscribers := prometheusOperationalRuntimeTestResource("high-subscribers", "info", "false", "30", "64")
	disabledLongReload := prometheusOperationalRuntimeTestResource("disabled-long-reload", "info", "false", "120", "16")
	flagsUnavailable := prometheusOperationalRuntimeTestResource("flags-unavailable", "debug", "true", "120", "64")
	flagsUnavailable.Metadata[model.MetadataPrometheusFlagsAvailable] = "false"
	wrongSource := prometheusOperationalRuntimeTestResource("wrong-source", "debug", "true", "120", "64")
	wrongSource.Source.System = "thanos"
	inactive := prometheusOperationalRuntimeTestResource("inactive", "debug", "true", "120", "64")
	inactive.Status = model.ResourceStatusDeprecated
	missing := prometheusOperationalRuntimeTestResource("missing", "", "", "", "")
	delete(missing.Metadata, model.MetadataPrometheusLogLevel)
	delete(missing.Metadata, model.MetadataPrometheusConfigAutoReloadEnabled)
	delete(missing.Metadata, model.MetadataPrometheusAutoReloadIntervalSeconds)
	delete(missing.Metadata, model.MetadataPrometheusMaxNotificationSubscribers)
	malformed := prometheusOperationalRuntimeTestResource("malformed", "verbose", "true", "slow", "many")

	for _, resource := range []model.Resource{
		defaults, debug, longReload, highSubscribers, disabledLongReload,
		flagsUnavailable, wrongSource, inactive, missing, malformed,
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
		{NewPrometheusDebugLoggingAnalyzer(), "debug", "PrometheusDebugLogging", model.FindingCategoryCost},
		{NewPrometheusLongAutoReloadIntervalAnalyzer(), "long-reload", "PrometheusLongAutoReloadInterval", model.FindingCategoryReliability},
		{NewPrometheusHighNotificationSubscriberLimitAnalyzer(), "high-subscribers", "PrometheusHighNotificationSubscriberLimit", model.FindingCategoryCost},
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

func prometheusOperationalRuntimeTestResource(id, level, autoReload, interval, subscribers string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTSDB,
		Name:   "prometheus runtime",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "test"},
		Metadata: map[string]string{
			model.MetadataPrometheusFlagsAvailable:             "true",
			model.MetadataPrometheusLogLevel:                   level,
			model.MetadataPrometheusConfigAutoReloadEnabled:    autoReload,
			model.MetadataPrometheusAutoReloadIntervalSeconds:  interval,
			model.MetadataPrometheusMaxNotificationSubscribers: subscribers,
		},
	}
}
