package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/rule"
	"monicheck/internal/storage"
)

func TestRuleEngineAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	metric := model.Resource{
		ID:       "metric-1",
		Type:     model.ResourceTypeMetric,
		Name:     "legacy_queue_depth",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{model.MetadataSeriesCount: "1200"},
	}
	if err := store.Resources.Upsert(ctx, metric); err != nil {
		t.Fatalf("upsert metric: %v", err)
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewRuleEngineAnalyzer([]rule.Rule{
		{
			ID:          "unused-high-cardinality",
			Name:        "Unused High Cardinality Metric",
			Version:     "0.1.0",
			Type:        rule.TypeCost,
			Scope:       []model.ResourceType{model.ResourceTypeMetric},
			Condition:   rule.Condition{Expression: `type == "Metric" AND used_by == 0 AND cardinality > 1000`},
			Severity:    model.SeverityWarning,
			FindingType: "RuleHighCardinalityUnusedMetric",
		},
	}).Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Metadata["rule_id"] != "unused-high-cardinality" {
		t.Fatalf("expected rule metadata to be set")
	}
	if findings[0].Category != model.FindingCategoryCost {
		t.Fatalf("expected cost finding, got %s", findings[0].Category)
	}
	if err := store.Findings.ReplaceOpenByAnalyzer(ctx, RuleEngineAnalyzerID, findings); err != nil {
		t.Fatalf("replace findings: %v", err)
	}
	filtered, err := store.Findings.List(ctx, storage.FindingFilter{RuleID: "unused-high-cardinality"})
	if err != nil {
		t.Fatalf("list findings by rule: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 rule-filtered finding, got %d", len(filtered))
	}
}
