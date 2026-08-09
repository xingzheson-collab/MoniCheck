package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestPrometheusStorageSafetyAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	serverHealthy := prometheusStorageSafetyTestResource("server-healthy", "false", "true", "false", "false")
	serverWALDisabled := prometheusStorageSafetyTestResource("server-wal-disabled", "false", "false", "false", "false")
	serverLockDisabled := prometheusStorageSafetyTestResource("server-lock-disabled", "false", "true", "true", "false")
	agentLockDisabled := prometheusStorageSafetyTestResource("agent-lock-disabled", "true", "false", "true", "true")
	agentTSDBFlags := prometheusStorageSafetyTestResource("agent-tsdb-flags", "true", "false", "true", "false")
	serverAgentFlag := prometheusStorageSafetyTestResource("server-agent-flag", "false", "true", "false", "true")
	unavailable := prometheusStorageSafetyTestResource("unavailable", "false", "false", "true", "true")
	unavailable.Metadata[model.MetadataPrometheusFlagsAvailable] = "false"
	wrongSource := prometheusStorageSafetyTestResource("wrong-source", "false", "false", "true", "true")
	wrongSource.Source.System = "thanos"
	missing := prometheusStorageSafetyTestResource("missing", "false", "", "", "")
	delete(missing.Metadata, model.MetadataPrometheusTSDBWALCompression)
	delete(missing.Metadata, model.MetadataPrometheusTSDBNoLockfile)
	delete(missing.Metadata, model.MetadataPrometheusAgentNoLockfile)

	for _, resource := range []model.Resource{
		serverHealthy, serverWALDisabled, serverLockDisabled, agentLockDisabled,
		agentTSDBFlags, serverAgentFlag, unavailable, wrongSource, missing,
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
		{NewPrometheusTSDBWALCompressionDisabledAnalyzer(), "server-wal-disabled", "PrometheusTSDBWALCompressionDisabled", model.FindingCategoryCost},
		{NewPrometheusTSDBLockfileDisabledAnalyzer(), "server-lock-disabled", "PrometheusTSDBLockfileDisabled", model.FindingCategoryReliability},
		{NewPrometheusAgentLockfileDisabledAnalyzer(), "agent-lock-disabled", "PrometheusAgentLockfileDisabled", model.FindingCategoryReliability},
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

func prometheusStorageSafetyTestResource(id, agentMode, tsdbWALCompression, tsdbNoLockfile, agentNoLockfile string) model.Resource {
	return model.Resource{
		ID:     id,
		UID:    id,
		Type:   model.ResourceTypeTSDB,
		Name:   "prometheus storage",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "test"},
		Metadata: map[string]string{
			model.MetadataPrometheusFlagsAvailable:     "true",
			model.MetadataPrometheusAgentMode:          agentMode,
			model.MetadataPrometheusTSDBWALCompression: tsdbWALCompression,
			model.MetadataPrometheusTSDBNoLockfile:     tsdbNoLockfile,
			model.MetadataPrometheusAgentNoLockfile:    agentNoLockfile,
		},
	}
}
