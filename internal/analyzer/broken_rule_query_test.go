package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestBrokenRuleQueryAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	metric := model.Resource{
		ID:     "metric-http-requests",
		Type:   model.ResourceTypeMetric,
		Name:   "http_requests_total",
		Status: model.ResourceStatusActive,
	}
	validRule := model.Resource{
		ID:     "rule-valid",
		Type:   model.ResourceTypeAlertRule,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(http_requests_total[5m])) > 10",
		},
	}
	missingQueryRule := model.Resource{
		ID:       "rule-missing-query",
		Type:     model.ResourceTypeAlertRule,
		Name:     "MissingQuery",
		Status:   model.ResourceStatusActive,
		Metadata: map[string]string{},
	}
	unresolvedQueryRule := model.Resource{
		ID:     "rule-unresolved-query",
		Type:   model.ResourceTypeRecordingRule,
		Name:   "ScalarOnly",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "vector(1)",
		},
	}
	danglingRule := model.Resource{
		ID:     "rule-dangling",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DanglingMetric",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataPromQL: "sum(rate(missing_metric_total[5m])) > 0",
		},
	}
	disabledRule := model.Resource{
		ID:     "rule-disabled",
		Type:   model.ResourceTypeAlertRule,
		Name:   "DisabledMissingQuery",
		Status: model.ResourceStatusActive,
		Metadata: map[string]string{
			model.MetadataDisabled: "true",
		},
	}

	for _, resource := range []model.Resource{metric, validRule, missingQueryRule, unresolvedQueryRule, danglingRule, disabledRule} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	for _, relationship := range []model.Relationship{
		{ID: "valid-uses-metric", FromID: validRule.ID, ToID: metric.ID, Type: model.RelationshipUses},
		{ID: "dangling-uses-metric", FromID: danglingRule.ID, ToID: "metric-missing", Type: model.RelationshipUses, Metadata: map[string]string{model.MetadataMetricInventoryBinding: "EXACT"}},
	} {
		if err := store.Relationships.Upsert(ctx, relationship); err != nil {
			t.Fatalf("upsert relationship: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewBrokenRuleQueryAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	found := map[string]string{}
	for _, finding := range findings {
		found[finding.Resource.ID] = finding.Type
		if finding.Metadata["analyzer_id"] != BrokenRuleQueryAnalyzerID {
			t.Fatalf("expected analyzer metadata %s, got %#v", BrokenRuleQueryAnalyzerID, finding.Metadata)
		}
	}
	if found[missingQueryRule.ID] != "MissingRuleQuery" {
		t.Fatalf("expected missing query finding, got %#v", found)
	}
	if found[unresolvedQueryRule.ID] != "UnresolvedRuleQueryMetric" {
		t.Fatalf("expected unresolved query finding, got %#v", found)
	}
	if found[danglingRule.ID] != "AlertRuleMetricNotCollected" {
		t.Fatalf("expected dangling metric finding, got %#v", found)
	}
	for _, finding := range findings {
		if finding.Resource.ID == danglingRule.ID && finding.Severity != model.SeverityCritical {
			t.Fatalf("expected ineffective alert to be critical, got %#v", finding)
		}
	}
	if found[validRule.ID] != "" || found[disabledRule.ID] != "" {
		t.Fatalf("did not expect valid or disabled rule findings, got %#v", found)
	}
}
