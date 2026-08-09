package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusAgentStorageAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	defaults := prometheusAgentStorageTestResource("defaults", "true", "14400")
	compressionDisabled := prometheusAgentStorageTestResource("compression-disabled", "false", "14400")
	longRetention := prometheusAgentStorageTestResource("long-retention", "true", "28800")
	longMinimumRetention := prometheusAgentStorageTestResource("long-minimum-retention", "true", "14400")
	longMinimumRetention.Metadata[model.MetadataPrometheusAgentRetentionMinSeconds] = "900"
	shortFlushDeadline := prometheusAgentStorageTestResource("short-flush-deadline", "true", "14400")
	shortFlushDeadline.Metadata[model.MetadataPrometheusRemoteFlushDeadline] = "15"
	serverMode := prometheusAgentStorageTestResource("server-mode", "false", "28800")
	serverMode.Metadata[model.MetadataPrometheusAgentMode] = "false"
	serverMode.Metadata[model.MetadataPrometheusAgentRetentionMinSeconds] = "900"
	serverMode.Metadata[model.MetadataPrometheusRemoteFlushDeadline] = "15"
	modeMissing := prometheusAgentStorageTestResource("mode-missing", "false", "28800")
	delete(modeMissing.Metadata, model.MetadataPrometheusAgentMode)
	modeMissing.Metadata[model.MetadataPrometheusAgentRetentionMinSeconds] = "900"
	modeMissing.Metadata[model.MetadataPrometheusRemoteFlushDeadline] = "15"
	flagsUnavailable := prometheusAgentStorageTestResource("flags-unavailable", "false", "28800")
	flagsUnavailable.Metadata[model.MetadataPrometheusFlagsAvailable] = "false"
	flagsUnavailable.Metadata[model.MetadataPrometheusAgentRetentionMinSeconds] = "900"
	flagsUnavailable.Metadata[model.MetadataPrometheusRemoteFlushDeadline] = "15"
	wrongSource := prometheusAgentStorageTestResource("wrong-source", "false", "28800")
	wrongSource.Source.System = "thanos"
	wrongSource.Metadata[model.MetadataPrometheusAgentRetentionMinSeconds] = "900"
	wrongSource.Metadata[model.MetadataPrometheusRemoteFlushDeadline] = "15"
	missing := prometheusAgentStorageTestResource("missing", "", "")
	delete(missing.Metadata, model.MetadataPrometheusAgentWALCompression)
	delete(missing.Metadata, model.MetadataPrometheusAgentRetentionMaxSeconds)
	delete(missing.Metadata, model.MetadataPrometheusAgentRetentionMinSeconds)
	delete(missing.Metadata, model.MetadataPrometheusRemoteFlushDeadline)

	for _, resource := range []model.Resource{
		defaults, compressionDisabled, longRetention, longMinimumRetention, shortFlushDeadline, serverMode, modeMissing,
		flagsUnavailable, wrongSource, missing,
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
		{NewPrometheusAgentWALCompressionDisabledAnalyzer(), "compression-disabled", "PrometheusAgentWALCompressionDisabled", model.FindingCategoryCost},
		{NewPrometheusAgentLongWALRetentionAnalyzer(), "long-retention", "PrometheusAgentLongWALRetention", model.FindingCategoryCost},
		{NewPrometheusAgentLongWALMinimumRetentionAnalyzer(), "long-minimum-retention", "PrometheusAgentLongWALMinimumRetention", model.FindingCategoryCost},
		{NewPrometheusAgentShortRemoteFlushDeadlineAnalyzer(), "short-flush-deadline", "PrometheusAgentShortRemoteFlushDeadline", model.FindingCategoryReliability},
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

func prometheusAgentStorageTestResource(id, compression, retentionMaxSeconds string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTSDB,
		Name:   "prometheus Agent",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "test"},
		Metadata: map[string]string{
			model.MetadataPrometheusFlagsAvailable:           "true",
			model.MetadataPrometheusAgentMode:                "true",
			model.MetadataPrometheusAgentWALCompression:      compression,
			model.MetadataPrometheusAgentRetentionMinSeconds: "300",
			model.MetadataPrometheusAgentRetentionMaxSeconds: retentionMaxSeconds,
			model.MetadataPrometheusRemoteFlushDeadline:      "60",
		},
	}
}
