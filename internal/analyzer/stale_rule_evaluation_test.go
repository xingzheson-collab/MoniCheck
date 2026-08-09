package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestStaleRuleEvaluationAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	resources := []model.Resource{
		{
			ID:   "alert-rule-recent",
			Type: model.ResourceTypeAlertRule,
			Name: "RecentRule",
			Metadata: map[string]string{
				model.MetadataEvaluationInterval: "1m",
				model.MetadataLastEvaluation:     now.Add(-2 * time.Minute).Format(time.RFC3339),
			},
			Status: model.ResourceStatusActive,
		},
		{
			ID:   "recording-rule-stale",
			Type: model.ResourceTypeRecordingRule,
			Name: "StaleRule",
			Metadata: map[string]string{
				model.MetadataEvaluationInterval: "1m",
				model.MetadataLastEvaluation:     now.Add(-10 * time.Minute).Format(time.RFC3339),
			},
			Status: model.ResourceStatusActive,
		},
		{
			ID:       "alert-rule-missing-metadata",
			Type:     model.ResourceTypeAlertRule,
			Name:     "MissingMetadataRule",
			Metadata: map[string]string{},
			Status:   model.ResourceStatusActive,
		},
		{
			ID:   "alert-rule-disabled-stale",
			Type: model.ResourceTypeAlertRule,
			Name: "DisabledStaleRule",
			Metadata: map[string]string{
				model.MetadataEvaluationInterval: "1m",
				model.MetadataLastEvaluation:     now.Add(-10 * time.Minute).Format(time.RFC3339),
				model.MetadataDisabled:           "true",
			},
			Status: model.ResourceStatusActive,
		},
		{
			ID:   "recording-rule-deprecated-stale",
			Type: model.ResourceTypeRecordingRule,
			Name: "DeprecatedStaleRule",
			Metadata: map[string]string{
				model.MetadataEvaluationInterval: "1m",
				model.MetadataLastEvaluation:     now.Add(-10 * time.Minute).Format(time.RFC3339),
			},
			Status: model.ResourceStatusDeprecated,
		},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewStaleRuleEvaluationAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Type != "StaleRuleEvaluation" {
		t.Fatalf("expected StaleRuleEvaluation, got %s", finding.Type)
	}
	if finding.Resource.ID != "recording-rule-stale" {
		t.Fatalf("expected stale rule finding, got %s", finding.Resource.ID)
	}
	if finding.Metadata["threshold"] != "3m0s" {
		t.Fatalf("expected interval-based threshold metadata, got %#v", finding.Metadata)
	}
}

func TestStaleRuleEvaluationAnalyzerFallbackThreshold(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	resource := model.Resource{
		ID:   "rule",
		Type: model.ResourceTypeAlertRule,
		Name: "FallbackThresholdRule",
		Metadata: map[string]string{
			model.MetadataLastEvaluation: now.Add(-10 * time.Minute).Format(time.RFC3339),
		},
		Status: model.ResourceStatusActive,
	}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewStaleRuleEvaluationAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config: map[string]any{
			"stale_rule_evaluation_threshold": "5m",
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected fallback threshold finding, got %d", len(findings))
	}
	if findings[0].Metadata["threshold"] != "5m0s" {
		t.Fatalf("expected fallback threshold metadata, got %#v", findings[0].Metadata)
	}
}
