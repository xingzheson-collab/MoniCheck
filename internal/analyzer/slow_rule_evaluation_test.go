package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestSlowRuleEvaluationAnalyzer(t *testing.T) {
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	resources := []model.Resource{
		{
			ID:   "alert-rule-fast",
			Type: model.ResourceTypeAlertRule,
			Name: "FastRule",
			Metadata: map[string]string{
				model.MetadataEvaluationInterval: "1m",
				model.MetadataEvaluationTime:     "10s",
			},
			CreatedAt: now,
			UpdatedAt: now,
			Status:    model.ResourceStatusActive,
		},
		{
			ID:   "recording-rule-slow",
			Type: model.ResourceTypeRecordingRule,
			Name: "SlowRule",
			Metadata: map[string]string{
				model.MetadataEvaluationInterval: "30s",
				model.MetadataEvaluationTime:     "25s",
			},
			CreatedAt: now,
			UpdatedAt: now,
			Status:    model.ResourceStatusActive,
		},
		{
			ID:        "alert-rule-missing-metadata",
			Type:      model.ResourceTypeAlertRule,
			Name:      "MissingMetadataRule",
			Metadata:  map[string]string{},
			CreatedAt: now,
			UpdatedAt: now,
			Status:    model.ResourceStatusActive,
		},
		{
			ID:   "alert-rule-disabled-slow",
			Type: model.ResourceTypeAlertRule,
			Name: "DisabledSlowRule",
			Metadata: map[string]string{
				model.MetadataEvaluationInterval: "30s",
				model.MetadataEvaluationTime:     "25s",
				model.MetadataDisabled:           "true",
			},
			CreatedAt: now,
			UpdatedAt: now,
			Status:    model.ResourceStatusActive,
		},
		{
			ID:   "recording-rule-deprecated-slow",
			Type: model.ResourceTypeRecordingRule,
			Name: "DeprecatedSlowRule",
			Metadata: map[string]string{
				model.MetadataEvaluationInterval: "30s",
				model.MetadataEvaluationTime:     "25s",
			},
			CreatedAt: now,
			UpdatedAt: now,
			Status:    model.ResourceStatusDeprecated,
		},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(context.Background(), resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	analyzer := NewSlowRuleEvaluationAnalyzer()
	findings, err := analyzer.Execute(context.Background(), Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Type != "SlowRuleEvaluation" {
		t.Fatalf("expected SlowRuleEvaluation, got %s", finding.Type)
	}
	if finding.Resource.ID != "recording-rule-slow" {
		t.Fatalf("expected slow rule finding, got %s", finding.Resource.ID)
	}
	if finding.Metadata["ratio"] != "0.8333" {
		t.Fatalf("expected ratio metadata, got %#v", finding.Metadata)
	}
}

func TestSlowRuleEvaluationAnalyzerConfiguredThreshold(t *testing.T) {
	store := storage.NewMemoryStore()
	now := time.Now().UTC()
	resource := model.Resource{
		ID:   "rule",
		Type: model.ResourceTypeAlertRule,
		Name: "ConfiguredThresholdRule",
		Metadata: map[string]string{
			model.MetadataEvaluationInterval: "30s",
			model.MetadataEvaluationTime:     "25s",
		},
		CreatedAt: now,
		UpdatedAt: now,
		Status:    model.ResourceStatusActive,
	}
	if err := store.Resources.Upsert(context.Background(), resource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	analyzer := NewSlowRuleEvaluationAnalyzer()
	findings, err := analyzer.Execute(context.Background(), Context{
		Resources: store.Resources,
		Config: map[string]any{
			"slow_rule_evaluation_ratio_threshold": 0.9,
		},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
