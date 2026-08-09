package analyzer

import (
	"context"
	"testing"

	"monicheck/internal/graph"
	"monicheck/internal/model"
	"monicheck/internal/storage"
)

func TestAlertWithoutReceiverAnalyzer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	withReceiver := model.Resource{
		ID:     "alert-with-receiver",
		Type:   model.ResourceTypeAlert,
		Name:   "APIHighErrorRate",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:with-receiver"},
		Metadata: map[string]string{
			model.MetadataAlertState:    "active",
			model.MetadataReceiverNames: "pagerduty",
		},
	}
	withoutReceiver := model.Resource{
		ID:     "alert-without-receiver",
		Type:   model.ResourceTypeAlert,
		Name:   "DBDown",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:without-receiver"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
		},
	}
	prometheusAlert := model.Resource{
		ID:     "prometheus-alert",
		Type:   model.ResourceTypeAlert,
		Name:   "PrometheusAlert",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "prometheus", Instance: "local", ExternalID: "alert:prom"},
		Metadata: map[string]string{
			model.MetadataAlertState: "active",
		},
	}
	resolvedAlert := model.Resource{
		ID:     "resolved-alert",
		Type:   model.ResourceTypeAlert,
		Name:   "ResolvedAlert",
		Status: model.ResourceStatusActive,
		Source: model.SourceInfo{System: "alertmanager", Instance: "local", ExternalID: "alert:resolved"},
		Metadata: map[string]string{
			model.MetadataAlertState: "resolved",
		},
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
	for _, resource := range []model.Resource{withReceiver, withoutReceiver, prometheusAlert, resolvedAlert, deprecatedAlert} {
		if err := store.Resources.Upsert(ctx, resource); err != nil {
			t.Fatalf("upsert resource: %v", err)
		}
	}
	resourceGraph, err := graph.Build(ctx, store.Resources, store.Relationships)
	if err != nil {
		t.Fatalf("build graph: %v", err)
	}

	findings, err := NewAlertWithoutReceiverAnalyzer().Execute(ctx, Context{Resources: store.Resources, Graph: resourceGraph})
	if err != nil {
		t.Fatalf("execute analyzer: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource.ID != withoutReceiver.ID || findings[0].Severity != model.SeverityCritical {
		t.Fatalf("expected critical receiver finding, got %#v", findings[0])
	}
}
