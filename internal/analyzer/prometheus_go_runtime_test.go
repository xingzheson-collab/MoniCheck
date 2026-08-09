package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusGoRuntimeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	defaults := prometheusGoRuntimeTestResource("defaults", "true", "true", "0.9")
	gomaxprocsDisabled := prometheusGoRuntimeTestResource("gomaxprocs-disabled", "false", "true", "0.9")
	gomemlimitDisabled := prometheusGoRuntimeTestResource("gomemlimit-disabled", "true", "false", "0.9")
	highRatio := prometheusGoRuntimeTestResource("high-ratio", "true", "true", "0.95")
	flagsUnavailable := prometheusGoRuntimeTestResource("flags-unavailable", "false", "false", "0.95")
	flagsUnavailable.Metadata[model.MetadataPrometheusFlagsAvailable] = "false"
	wrongSource := prometheusGoRuntimeTestResource("wrong-source", "false", "false", "0.95")
	wrongSource.Source.System = "thanos"
	inactive := prometheusGoRuntimeTestResource("inactive", "false", "false", "0.95")
	inactive.Status = model.ResourceStatusDeprecated
	missing := prometheusGoRuntimeTestResource("missing", "", "", "")
	delete(missing.Metadata, model.MetadataPrometheusAutoGOMAXPROCSEnabled)
	delete(missing.Metadata, model.MetadataPrometheusAutoGOMEMLIMITEnabled)
	delete(missing.Metadata, model.MetadataPrometheusAutoGOMEMLIMITRatio)
	malformed := prometheusGoRuntimeTestResource("malformed", "disabled", "disabled", "aggressive")

	for _, resource := range []model.Resource{
		defaults, gomaxprocsDisabled, gomemlimitDisabled, highRatio,
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
		{NewPrometheusAutoGOMAXPROCSDisabledAnalyzer(), "gomaxprocs-disabled", "PrometheusAutoGOMAXPROCSDisabled", model.FindingCategoryCost},
		{NewPrometheusAutoGOMEMLIMITDisabledAnalyzer(), "gomemlimit-disabled", "PrometheusAutoGOMEMLIMITDisabled", model.FindingCategoryReliability},
		{NewPrometheusHighAutoGOMEMLIMITRatioAnalyzer(), "high-ratio", "PrometheusHighAutoGOMEMLIMITRatio", model.FindingCategoryReliability},
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

func prometheusGoRuntimeTestResource(id, gomaxprocs, gomemlimit, ratio string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTSDB,
		Name:   "prometheus runtime",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "test"},
		Metadata: map[string]string{
			model.MetadataPrometheusFlagsAvailable:        "true",
			model.MetadataPrometheusAutoGOMAXPROCSEnabled: gomaxprocs,
			model.MetadataPrometheusAutoGOMEMLIMITEnabled: gomemlimit,
			model.MetadataPrometheusAutoGOMEMLIMITRatio:   ratio,
		},
	}
}
