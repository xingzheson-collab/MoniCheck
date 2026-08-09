package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusWebRuntimeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	defaults := prometheusWebRuntimeTestResource("defaults", "1048576", "512", "300")
	largeFrame := prometheusWebRuntimeTestResource("large-frame", "2097152", "512", "300")
	highConnections := prometheusWebRuntimeTestResource("high-connections", "1048576", "1024", "300")
	longTimeout := prometheusWebRuntimeTestResource("long-timeout", "1048576", "512", "600")
	agent := prometheusWebRuntimeTestResource("agent", "2097152", "512", "300")
	agent.Metadata[model.MetadataPrometheusAgentMode] = "true"
	unavailable := prometheusWebRuntimeTestResource("unavailable", "2097152", "1024", "600")
	unavailable.Metadata[model.MetadataPrometheusFlagsAvailable] = "false"
	wrongSource := prometheusWebRuntimeTestResource("wrong-source", "2097152", "1024", "600")
	wrongSource.Source.System = "thanos"
	missing := prometheusWebRuntimeTestResource("missing", "", "", "")
	delete(missing.Metadata, model.MetadataPrometheusRemoteReadFrameBytes)
	delete(missing.Metadata, model.MetadataPrometheusWebMaxConnections)
	delete(missing.Metadata, model.MetadataPrometheusWebReadTimeoutSeconds)

	for _, resource := range []model.Resource{
		defaults, largeFrame, highConnections, longTimeout, agent, unavailable, wrongSource, missing,
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
		{NewPrometheusLargeRemoteReadFrameAnalyzer(), "large-frame", "PrometheusLargeRemoteReadFrame", model.FindingCategoryCost},
		{NewPrometheusHighWebConnectionLimitAnalyzer(), "high-connections", "PrometheusHighWebConnectionLimit", model.FindingCategoryCost},
		{NewPrometheusLongWebReadTimeoutAnalyzer(), "long-timeout", "PrometheusLongWebReadTimeout", model.FindingCategoryReliability},
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

func prometheusWebRuntimeTestResource(id, frameBytes, maxConnections, readTimeoutSeconds string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTSDB,
		Name:   "prometheus TSDB",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "test"},
		Metadata: map[string]string{
			model.MetadataPrometheusFlagsAvailable:        "true",
			model.MetadataPrometheusAgentMode:             "false",
			model.MetadataPrometheusRemoteReadFrameBytes:  frameBytes,
			model.MetadataPrometheusWebMaxConnections:     maxConnections,
			model.MetadataPrometheusWebReadTimeoutSeconds: readTimeoutSeconds,
		},
	}
}
