package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusMetadataIOAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	metadataWAL := prometheusMetadataIOTestResource("metadata-wal")
	metadataWAL.Metadata[model.MetadataPrometheusAgentMode] = "true"
	metadataWAL.Metadata[model.MetadataPrometheusMetadataWALRecordsEnabled] = "true"
	typeUnit := prometheusMetadataIOTestResource("type-unit")
	typeUnit.Metadata[model.MetadataPrometheusTypeUnitLabelsEnabled] = "true"
	uncached := prometheusMetadataIOTestResource("uncached")
	uncached.Metadata[model.MetadataPrometheusUncachedIOEnabled] = "true"

	agentUncached := prometheusMetadataIOTestResource("agent-uncached")
	agentUncached.Metadata[model.MetadataPrometheusAgentMode] = "true"
	agentUncached.Metadata[model.MetadataPrometheusUncachedIOEnabled] = "true"
	flagsUnavailable := prometheusMetadataIOTestResource("flags-unavailable")
	flagsUnavailable.Metadata[model.MetadataPrometheusFlagsAvailable] = "false"
	flagsUnavailable.Metadata[model.MetadataPrometheusMetadataWALRecordsEnabled] = "true"
	wrongSource := prometheusMetadataIOTestResource("wrong-source")
	wrongSource.Source.System = "thanos"
	wrongSource.Metadata[model.MetadataPrometheusTypeUnitLabelsEnabled] = "true"
	inactive := prometheusMetadataIOTestResource("inactive")
	inactive.Status = model.ResourceStatusDeprecated
	inactive.Metadata[model.MetadataPrometheusTypeUnitLabelsEnabled] = "true"
	missing := prometheusMetadataIOTestResource("missing")

	for _, resource := range []model.Resource{
		metadataWAL, typeUnit, uncached, agentUncached,
		flagsUnavailable, wrongSource, inactive, missing,
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
		{NewPrometheusMetadataWALRecordsAnalyzer(), "metadata-wal", "PrometheusMetadataWALRecordsEnabled", model.FindingCategoryCost},
		{NewPrometheusTypeUnitLabelsAnalyzer(), "type-unit", "PrometheusTypeAndUnitLabelsEnabled", model.FindingCategoryCost},
		{NewPrometheusExperimentalUncachedIOAnalyzer(), "uncached", "PrometheusExperimentalUncachedIO", model.FindingCategoryReliability},
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

func prometheusMetadataIOTestResource(id string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTSDB,
		Name:   "prometheus runtime",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "test"},
		Metadata: map[string]string{
			model.MetadataPrometheusFlagsAvailable: "true",
			model.MetadataPrometheusAgentMode:      "false",
		},
	}
}
