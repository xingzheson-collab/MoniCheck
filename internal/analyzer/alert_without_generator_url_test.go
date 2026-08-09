package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestAlertWithoutGeneratorURLAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	withGenerator := model.Resource{
		ID:     "alert-with-generator",
		Type:   model.ResourceTypeAlert,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:with-generator"},
		Metadata: map[string]string{
			model.MetadataAlertState:   "active",
			model.MetadataGeneratorURL: "http://prometheus/graph?g0.expr=...",
		},
	}
	withoutGenerator := model.Resource{
		ID:     "alert-without-generator",
		Type:   model.ResourceTypeAlert,
		Name:   "DBDown",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:without-generator"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
		},
	}
	suppressedAlert := model.Resource{
		ID:     "alert-suppressed",
		Type:   model.ResourceTypeAlert,
		Name:   "Suppressed",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:suppressed"},
		Metadata: map[string]string{
			model.MetadataAlertState: "suppressed",
		},
	}
	prometheusAlert := model.Resource{
		ID:     "prometheus-alert",
		Type:   model.ResourceTypeAlert,
		Name:   "PrometheusAlert",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "alert:prom"},
	}
	deprecatedAlert := model.Resource{
		ID:     "deprecated-alert",
		Type:   model.ResourceTypeAlert,
		Name:   "DeprecatedAlert",
		Status: model.ResourceStatusDeprecated,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:deprecated"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
		},
	}
	for _, resource := range []model.Resource{withGenerator, withoutGenerator, suppressedAlert, prometheusAlert, deprecatedAlert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewAlertWithoutGeneratorURLAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Type != "AlertWithoutGeneratorURL" || findings[0].Resource.ID != withoutGenerator.ID {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}
