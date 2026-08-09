package analyzer

import (
	"context"
	"testing"
	"time"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestMissingAlertDurationAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	now := time.Now().UTC()

	resources := []model.Resource{
		{
			ID:        "rule-without-duration",
			Type:      model.ResourceTypeAlertRule,
			Name:      "HighErrorRate",
			Labels:    map[string]string{"severity": "critical"},
			Metadata:  map[string]string{},
			Status:    model.ResourceStatusActive,
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        "rule-with-duration",
			Type:      model.ResourceTypeAlertRule,
			Name:      "HighLatency",
			Labels:    map[string]string{"severity": "warning"},
			Metadata:  map[string]string{model.MetadataAlertFor: "5m"},
			Status:    model.ResourceStatusActive,
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        "info-rule",
			Type:      model.ResourceTypeAlertRule,
			Name:      "InfoOnly",
			Labels:    map[string]string{"severity": "info"},
			Metadata:  map[string]string{},
			Status:    model.ResourceStatusActive,
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        "disabled-rule",
			Type:      model.ResourceTypeAlertRule,
			Name:      "Disabled",
			Labels:    map[string]string{"severity": "critical"},
			Metadata:  map[string]string{model.MetadataEnabled: "false"},
			Status:    model.ResourceStatusActive,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewMissingAlertDurationAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "MissingAlertDuration" || findings[0].Resource.ID != "rule-without-duration" {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}
