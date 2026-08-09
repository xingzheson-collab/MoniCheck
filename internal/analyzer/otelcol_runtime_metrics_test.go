package analyzer

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestOTelTailSamplingRuntimeAnalyzers(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	drops := otelcolRuntimeMetricsResource("drops", "true", "7", "2", "0")
	errors := otelcolRuntimeMetricsResource("errors", "true", "0", "0", "5")
	healthy := otelcolRuntimeMetricsResource("healthy", "true", "0", "0", "0")
	unavailable := otelcolRuntimeMetricsResource("unavailable", "false", "7", "2", "5")
	wrongSource := otelcolRuntimeMetricsResource("wrong-source", "true", "7", "2", "5")
	wrongSource.Source.System = "plugin"
	for _, resource := range []model.Resource{drops, errors, healthy, unavailable, wrongSource} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	tests := []struct {
		analyzer    Analyzer
		resourceID  string
		findingType string
		evidence    string
	}{
		{NewOTelTailSamplingRuntimeDropsAnalyzer(), drops.ID, "OTelTailSamplingRuntimeDrops", "7 trace(s) dropped"},
		{NewOTelTailSamplingPolicyErrorsAnalyzer(), errors.ID, "OTelTailSamplingPolicyEvaluationErrors", "5 policy evaluation error(s)"},
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
				findings[0].Severity != model.SeverityCritical ||
				findings[0].Category != model.FindingCategoryReliability ||
				!strings.Contains(findings[0].Evidence[0], test.evidence) ||
				model.DefaultFindingCategory(findings[0].Type, findings[0].Resource.Type) != model.FindingCategoryReliability {
				t.Fatalf("unexpected findings: %#v", findings)
			}
			encoded, err := json.Marshal(findings[0])
			if err != nil {
				t.Fatalf("marshal finding: %v", err)
			}
			for _, privateValue := range []string{"private-policy", "private-processor", "private-label"} {
				if strings.Contains(string(encoded), privateValue) {
					t.Fatalf("finding leaked %q: %s", privateValue, encoded)
				}
			}
		})
	}
}

func TestOTelTailSamplingRuntimeAnalyzersPreferCounterDeltas(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	stable := otelcolRuntimeMetricsResource("stable-delta", "true", "7", "2", "5")
	growing := otelcolRuntimeMetricsResource("growing-delta", "true", "8", "2", "7")
	for _, resource := range []*model.Resource{&stable, &growing} {
		resource.Metadata[model.MetadataOTelRuntimeCounterDeltaAvailable] = "true"
		resource.Metadata[model.MetadataOTelRuntimeCounterDeltaIntervalSeconds] = "60"
	}
	stable.Metadata[model.MetadataOTelTailSamplingDropDelta] = "0"
	stable.Metadata[model.MetadataOTelTailSamplingPolicyEvalErrorDelta] = "0"
	growing.Metadata[model.MetadataOTelTailSamplingDropDelta] = "1"
	growing.Metadata[model.MetadataOTelTailSamplingPolicyEvalErrorDelta] = "2"
	for _, resource := range []model.Resource{stable, growing} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, item := range []struct {
		analyzer Analyzer
		delta    string
	}{
		{NewOTelTailSamplingRuntimeDropsAnalyzer(), "1"},
		{NewOTelTailSamplingPolicyErrorsAnalyzer(), "2"},
	} {
		findings, err := item.analyzer.Execute(ctx, Context{Resources: store.Resources})
		if err != nil || len(findings) != 1 || findings[0].Resource.ID != growing.ID ||
			findings[0].Metadata["counter_evidence"] != "delta" ||
			findings[0].Metadata["counter_delta"] != item.delta ||
			findings[0].Metadata["counter_interval_seconds"] != "60" {
			t.Fatalf("unexpected delta finding for %s: findings=%#v err=%v", item.analyzer.ID(), findings, err)
		}
	}
}

func otelcolRuntimeMetricsResource(id, available, tooEarly, tooLarge, policyErrors string) model.Resource {
	return model.Resource{
		ID:     "otelcol-runtime-" + id,
		Type:   model.ResourceTypeInstance,
		Name:   "Collector " + id,
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "otelcol", ExternalID: id},
		Metadata: map[string]string{
			model.MetadataOTelRuntimeMetricsAvailable:      available,
			model.MetadataOTelTailSamplingDroppedTooEarly:  tooEarly,
			model.MetadataOTelTailSamplingDroppedTooLarge:  tooLarge,
			model.MetadataOTelTailSamplingPolicyEvalErrors: policyErrors,
		},
	}
}
