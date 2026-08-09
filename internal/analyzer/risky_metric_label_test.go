package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestRiskyMetricLabelAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resources := []model.Resource{
		{ID: "metric-safe", Type: model.ResourceTypeMetric, Name: "safe_metric", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataMetricLabelKeys: "instance,job,namespace"}},
		{ID: "metric-risky", Type: model.ResourceTypeMetric, Name: "request_metric", Status: model.ResourceStatusActive, Labels: map[string]string{"request-id": "abc"}, Metadata: map[string]string{model.MetadataMetricLabelKeys: "job,user_id,request-id"}},
		{ID: "metric-old", Type: model.ResourceTypeMetric, Name: "old_metric", Status: model.ResourceStatusDeprecated, Metadata: map[string]string{model.MetadataMetricLabelKeys: "session_id"}},
	}
	for _, resource := range resources {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}

	findings, err := NewRiskyMetricLabelAnalyzer().Execute(ctx, Context{Resources: store.Resources})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Resource.ID != "metric-risky" {
		t.Fatalf("expected one risky metric finding, got %#v", findings)
	}
	if findings[0].Metadata["risky_labels"] != "request-id,user_id" {
		t.Fatalf("expected sorted risky labels, got %#v", findings[0].Metadata)
	}
}

func TestRiskyMetricLabelAnalyzerCustomNames(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	resource := model.Resource{ID: "metric-tenant", Type: model.ResourceTypeMetric, Name: "tenant_metric", Status: model.ResourceStatusActive, Metadata: map[string]string{model.MetadataMetricLabelKeys: "tenant.slug"}}
	if err := store.Resources.Upsert(ctx, resource); err != nil {
		t.Fatalf("upsert resource: %v", err)
	}

	findings, err := NewRiskyMetricLabelAnalyzer().Execute(ctx, Context{
		Resources: store.Resources,
		Config:    map[string]any{"risky_metric_label_names": []string{"tenant_slug"}},
	})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 || findings[0].Metadata["risky_labels"] != "tenant.slug" {
		t.Fatalf("expected custom risky metric label finding, got %#v", findings)
	}
}
